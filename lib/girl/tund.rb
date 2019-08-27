require 'girl/head'
require 'girl/hex'
require 'girl/version'
require 'socket'

##
# Girl::Tund - tcp流量正常的到达目的地。远端。
#
# 两套关闭
# ========
#
# 1-1. dest.close -> ext.is_source_closed ? no -> send fin1 loop
# 1-2. recv got_fin1 -> break loop
# 1-3. recv fin2 -> send got_fin2 -> del ext
#
# 2-1. recv fin1 -> send got_fin1 -> ext.is_source_closed = true
# 2-2. all sent && ext.biggest_source_pack_id == ext.continue_source_pack_id -> add closing dest
# 2-3. dest.close -> ext.is_source_closed ? yes -> del ext -> loop send fin2
# 2-4. recv got_fin2 -> break loop
#
module Girl
  class Tund
    ##
    # roomd_port     roomd端口，roomd用于配对tun-tund
    # dest_chunk_dir 文件缓存目录，缓存dest写前
    # tund_chunk_dir 文件缓存目录，缓存tund写前
    #
    def initialize( roomd_port = 9090, dest_chunk_dir = '/tmp', tund_chunk_dir = '/tmp' )
      @roomd_port = roomd_port
      @dest_chunk_dir = dest_chunk_dir
      @tund_chunk_dir = tund_chunk_dir
      @hex = Girl::Hex.new
      @mutex = Mutex.new
      @reads = []
      @writes = []
      @closings = []
      @socks = {} # object_id => sock
      @roles = {} # sock => :ctlr / :roomd / :dest / :tund
      @infos = {} # sock => {}

      ctlr, ctlw = IO.pipe
      @ctlw = ctlw
      @roles[ ctlr ] = :ctlr
      @reads << ctlr
    end

    def looping
      puts 'looping'

      new_roomd

      loop do
        rs, ws = IO.select( @reads, @writes )

        @mutex.synchronize do
          rs.each do | sock |
            case @roles[ sock ]
            when :ctlr
              read_ctlr( sock )
            when :roomd
              read_roomd( sock )
            when :dest
              read_dest( sock )
            when :tund
              read_tund( sock )
            end
          end

          ws.each do | sock |
            case @roles[ sock ]
            when :dest
              write_dest( sock )
            when :tund
              write_tund( sock )
            end
          end
        end
      end
    rescue Interrupt => e
      puts e.class
      quit!
    end

    def quit!
      ctlmsg = [ 0, TUND_FIN ].pack( 'Q>C' )

      @roomd_info[ :tunds ].each do | tund, _ |
        tund_info = @infos[ tund ]

        if tund_info[ :tun_addr ]
          send_pack( tund, ctlmsg, tund_info[ :tun_addr ] )
        end
      end

      exit
    end

    private

    ##
    # read ctlr
    #
    def read_ctlr( ctlr )
      case ctlr.read( 1 ).unpack( 'C' ).first
      when CTL_CLOSE
        sock_id = ctlr.read( 8 ).unpack( 'Q>' ).first
        sock = @socks[ sock_id ]

        if sock
          puts "ctlr close #{ sock_id } #{ Time.new } p#{ Process.pid }"
          add_closing( sock )
        end
      when CTL_RESUME
        sock_id = ctlr.read( 8 ).unpack( 'Q>' ).first
        sock = @socks[ sock_id ]

        if sock
          puts "ctlr resume #{ sock_id } #{ Time.new } p#{ Process.pid }"
          add_write( sock )
        end
      end
    end

    ##
    # read roomd
    #
    def read_roomd( roomd )
      data, addrinfo, rflags, *controls = roomd.recvmsg
      sockaddr = addrinfo.to_sockaddr
      info = @infos[ roomd ]
      return if info[ :tunds ].any?{ | _, client | client == sockaddr }

      result = @hex.check( data, addrinfo )

      if result != :success
        puts "#{ result } #{ Time.new } p#{ Process.pid }"
        return
      end

      tund = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      tund.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )

      @socks[ tund.object_id ] = tund
      @roles[ tund ] = :tund
      @infos[ tund ] = {
        wbuffs: [],          # 写前缓存 [ dest_id, data ]
        caches: [],          # 块读出缓存 [ dest_id, data ]
        chunks: [],          # 块队列 filename
        spring: 0,           # 块后缀，结块时，如果块队列不为空，则自增，为空，则置为0
        tun_addr: nil,       # 近端地址
        source_ids: {},      # source_id => dest_id
        dest_exts: {},       # 长命信息 dest_id => {}
        fin1s: [],           # fin1: dest已关闭，等待对面收完流量 dest_id
        fin2s: [],           # fin2: 流量已收完 dest_id
        paused: false,       # 是否暂停写
        resendings: [],      # 重传队列 [ dest_id, pack_id ]
        last_traffic_at: nil # 收到有效流量，或者发出流量的时间戳
      }

      puts "#{ info[ :tunds ].size } tunds #{ Time.new } p#{ Process.pid }"
      info[ :tunds ][ tund ] = sockaddr
      tund_port = tund.local_address.ip_unpack.last

      ctlmsg = [
        0,
        TUND_PORT,
        tund_port
      ].pack( 'Q>Cn' )

      # puts "debug send TUND_PORT #{ tund_port } #{ Time.new } p#{ Process.pid }"
      send_pack( roomd, ctlmsg, sockaddr )
      add_read( tund )
      loop_expire( tund )
    end

    ##
    # read dest
    #
    def read_dest( dest )
      begin
        data = dest.read_nonblock( PACK_SIZE )
      rescue IO::WaitReadable, Errno::EINTR => e
        return
      rescue Exception => e
        add_closing( dest )
        return
      end

      info = @infos[ dest ]
      tund = info[ :tund ]

      if tund.closed?
        add_closing( dest )
        return
      end

      tund_info = @infos[ tund ]
      tund_info[ :wbuffs ] << [ dest.object_id, data ]

      if tund_info[ :wbuffs ].size >= WBUFFS_LIMIT
        spring = tund_info[ :chunks ].size > 0 ? ( tund_info[ :spring ] + 1 ) : 0
        filename = "#{ Process.pid }-#{ tund.object_id }.#{ spring }"
        chunk_path = File.join( @tund_chunk_dir, filename )
        IO.binwrite( chunk_path, tund_info[ :wbuffs ].map{ | dest_id, data | "#{ [ dest_id, data.bytesize ].pack( 'Q>n' ) }#{ data }" }.join )
        tund_info[ :chunks ] << filename
        tund_info[ :spring ] = spring
        tund_info[ :wbuffs ].clear
      end

      unless tund_info[ :paused ]
        add_write( tund )
      end
    end

    ##
    # read tund
    #
    def read_tund( tund )
      data, addrinfo, rflags, *controls = tund.recvmsg
      sockaddr = addrinfo.to_sockaddr
      now = Time.new
      info = @infos[ tund ]

      if info[ :tun_addr ].nil?
        info[ :tun_addr ] = sockaddr
        info[ :last_traffic_at ] = now
        loop_send_status( tund )
      elsif info[ :tun_addr ] != sockaddr
        puts "tun addr not match? #{ Addrinfo.new( info[ :tun_addr ] ).ip_unpack.inspect } #{ addrinfo.ip_unpack.inspect } #{ Time.new } p#{ Process.pid }"
        return
      end

      source_id = data[ 0, 8 ].unpack( 'Q>' ).first

      if source_id == 0
        ctl_num = data[ 8 ].unpack( 'C' ).first

        case ctl_num
        when A_NEW_SOURCE
          source_id = data[ 9, 8 ].unpack( 'Q>' ).first
          dest_id = info[ :source_ids ][ source_id ]

          unless dest_id
            dst_family, dst_port, dst_host = data[ 17, 8 ].unpack( 'nnN' )
            dest = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
            dest.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )

            begin
              dest.connect_nonblock( Socket.sockaddr_in( dst_port, dst_host ) )
            rescue IO::WaitWritable, Errno::EINTR
            end

            dest_id = dest.object_id

            @socks[ dest_id ] = dest
            @roles[ dest ] = :dest
            @infos[ dest ] = {
              tund: tund
            }

            info[ :dest_exts ][ dest_id ] = {
              dest: dest,
              wbuff: '',                  # 写前缓存
              cache: '',                  # 块读出缓存
              chunks: [],                 # 块队列，写前达到块大小时结一个块 filename
              spring: 0,                  # 块后缀，结块时，如果块队列不为空，则自增，为空，则置为0
              wmems: {},                  # 写后缓存 pack_id => data
              send_ats: {},               # 上一次发出时间 pack_id => send_at
              biggest_pack_id: 0,         # 发到几
              continue_source_pack_id: 0, # 收到几
              pieces: {},                 # 跳号包 source_pack_id => data
              source_id: source_id,       # 对面id
              is_source_closed: false,    # 对面是否已关闭
              biggest_source_pack_id: 0,  # 对面发到几
              completed_pack_id: 0,       # 完成到几（对面收到几）
              last_traffic_at: nil        # 收到有效流量，或者发出流量的时间戳
            }

            info[ :source_ids ][ source_id ] = dest_id
            add_read( dest )
          end

          ctlmsg = [
            0,
            PAIRED,
            source_id,
            dest_id
          ].pack( 'Q>CQ>Q>' )

          # puts "debug send PAIRED #{ source_id } #{ dest_id } #{ Time.new } p#{ Process.pid }"
          send_pack( tund, ctlmsg, info[ :tun_addr ] )
        when SOURCE_STATUS
          source_id, biggest_source_pack_id, continue_dest_pack_id  = data[ 9, 24 ].unpack( 'Q>Q>Q>' )
          dest_id = info[ :source_ids ][ source_id ]
          return unless dest_id

          ext = info[ :dest_exts ][ dest_id ]
          return unless ext

          # 更新对面发到几
          if biggest_source_pack_id > ext[ :biggest_source_pack_id ]
            ext[ :biggest_source_pack_id ] = biggest_source_pack_id
          end

          # 更新对面收到几，释放写后
          if continue_dest_pack_id > ext[ :completed_pack_id ]
            pack_ids = ext[ :wmems ].keys.select { | pack_id | pack_id <= continue_dest_pack_id }

            pack_ids.each do | pack_id |
              ext[ :wmems ].delete( pack_id )
              ext[ :send_ats ].delete( pack_id )
            end

            # puts "debug completed #{ continue_dest_pack_id }"
            ext[ :completed_pack_id ] = continue_dest_pack_id
          end

          if ext[ :is_source_closed ] && ( ext[ :biggest_source_pack_id ] == ext[ :continue_source_pack_id ] )
            add_write( ext[ :dest ] )
            return
          end

          # 发miss
          if !ext[ :dest ].closed? && ( ext[ :continue_source_pack_id ] < ext[ :biggest_source_pack_id ] )
            ranges = []
            curr_pack_id = ext[ :continue_source_pack_id ] + 1

            ext[ :pieces ].keys.sort.each do | pack_id |
              if pack_id > curr_pack_id
                ranges << [ curr_pack_id, pack_id - 1 ]
              end

              curr_pack_id = pack_id + 1
            end

            if curr_pack_id <= ext[ :biggest_source_pack_id ]
              ranges << [ curr_pack_id, ext[ :biggest_source_pack_id ] ]
            end

            # puts "debug #{ ext[ :continue_source_pack_id ] }/#{ ext[ :biggest_source_pack_id ] } send MISS #{ ranges.size }"
            ranges.each do | pack_id_begin, pack_id_end |
              ctlmsg = [
                0,
                MISS,
                source_id,
                pack_id_begin,
                pack_id_end
              ].pack( 'Q>CQ>Q>Q>' )

              send_pack( tund, ctlmsg, info[ :tun_addr ] )
            end
          end
        when MISS
          dest_id, pack_id_begin, pack_id_end = data[ 9, 24 ].unpack( 'Q>Q>Q>' )
          ext = info[ :dest_exts ][ dest_id ]
          return unless ext

          ( pack_id_begin..pack_id_end ).each do | pack_id |
            send_at = ext[ :send_ats ][ pack_id ]

            if send_at
              break if now - send_at < STATUS_INTERVAL

              info[ :resendings ] << [ dest_id, pack_id ]
            end
          end

          add_write( tund )
        when FIN1
          # puts "debug 2-1. recv fin1 -> send got_fin1 -> ext.is_source_closed = true #{ Time.new } p#{ Process.pid }"
          source_id = data[ 9, 8 ].unpack( 'Q>' ).first
          ctlmsg = [
            0,
            GOT_FIN1,
            source_id
          ].pack( 'Q>CQ>' )

          send_pack( tund, ctlmsg, info[ :tun_addr ] )

          dest_id = info[ :source_ids ][ source_id ]
          return unless dest_id

          ext = info[ :dest_exts ][ dest_id ]
          return unless ext

          ext[ :is_source_closed ] = true
        when GOT_FIN1
          # puts "debug 1-2. recv got_fin1 -> break loop #{ Time.new } p#{ Process.pid }"
          dest_id = data[ 9, 8 ].unpack( 'Q>' ).first
          info[ :fin1s ].delete( dest_id )
        when FIN2
          # puts "debug 1-3. recv fin2 -> send got_fin2 -> del ext #{ Time.new } p#{ Process.pid }"
          source_id = data[ 9, 8 ].unpack( 'Q>' ).first
          ctlmsg = [
            0,
            GOT_FIN2,
            source_id
          ].pack( 'Q>CQ>' )

          send_pack( tund, ctlmsg, info[ :tun_addr ] )

          dest_id = info[ :source_ids ].delete( source_id )
          return unless dest_id

          del_dest_ext( info, dest_id )
        when GOT_FIN2
          # puts "debug 2-4. recv got_fin2 -> break loop #{ Time.new } p#{ Process.pid }"
          dest_id = data[ 9, 8 ].unpack( 'Q>' ).first
          info[ :fin2s ].delete( dest_id )
        when TUN_FIN
          puts "recv tun fin #{ Time.new } p#{ Process.pid }"
          add_closing( tund )
        end

        return
      end

      dest_id = info[ :source_ids ][ source_id ]
      return unless dest_id

      ext = info[ :dest_exts ][ dest_id ]
      return if ext.nil? || ext[ :dest ].closed?

      pack_id = data[ 8, 8 ].unpack( 'Q>' ).first
      return if ( pack_id <= ext[ :continue_source_pack_id ] ) || ext[ :pieces ].include?( pack_id )

      data = data[ 16..-1 ]

      # 解混淆
      if pack_id == 1
        data = @hex.decode( data )
      end

      # 放进dest的写前缓存，跳号放碎片缓存
      if pack_id - ext[ :continue_source_pack_id ] == 1
        while ext[ :pieces ].include?( pack_id + 1 )
          data << ext[ :pieces ].delete( pack_id + 1 )
          pack_id += 1
        end

        ext[ :continue_source_pack_id ] = pack_id
        ext[ :wbuff ] << data

        if ext[ :wbuff ].bytesize >= CHUNK_SIZE
          spring = ext[ :chunks ].size > 0 ? ( ext[ :spring ] + 1 ) : 0
          filename = "#{ Process.pid }-#{ dest_id }.#{ spring }"
          chunk_path = File.join( @dest_chunk_dir, filename )
          IO.binwrite( chunk_path, ext[ :wbuff ] )
          ext[ :chunks ] << filename
          ext[ :spring ] = spring
          ext[ :wbuff ].clear
        end

        ext[ :last_traffic_at ] = now
        info[ :last_traffic_at ] = now
        add_write( ext[ :dest ] )
      else
        ext[ :pieces ][ pack_id ] = data
      end
    end

    ##
    # write dest
    #
    def write_dest( dest )
      if @closings.include?( dest )
        close_dest( dest )
        return
      end

      info = @infos[ dest ]
      tund = info[ :tund ]

      if tund.closed?
        add_closing( dest )
        return
      end

      tund_info = @infos[ tund ]
      ext = tund_info[ :dest_exts ][ dest.object_id ]

      # 取写前
      data = ext[ :cache ]
      from = :cache

      if data.empty?
        if ext[ :chunks ].any?
          path = File.join( @dest_chunk_dir, ext[ :chunks ].shift )

          begin
            data = IO.binread( path )
            File.delete( path )
          rescue Errno::ENOENT
            add_closing( dest )
            return
          end
        else
          data = ext[ :wbuff ]
          from = :wbuff
        end
      end

      if data.empty?
        if ext[ :is_source_closed ] && ( ext[ :biggest_source_pack_id ] == ext[ :continue_source_pack_id ] )
          # puts "debug 2-2. all sent && ext.biggest_source_pack_id == ext.continue_source_pack_id -> add closing dest #{ Time.new } p#{ Process.pid }"
          add_closing( dest )
          return
        end

        @writes.delete( dest )
        return
      end

      begin
        written = dest.write_nonblock( data )
      rescue IO::WaitWritable, Errno::EINTR => e
        ext[ from ] = data
        return
      rescue Exception => e
        add_closing( dest )
        return
      end

      data = data[ written..-1 ]
      ext[ from ] = data
    end

    ##
    # write tund
    #
    def write_tund( tund )
      if @closings.include?( tund )
        close_tund( tund )
        return
      end

      now = Time.new
      info = @infos[ tund ]

      # 重传
      while info[ :resendings ].any?
        dest_id, pack_id = info[ :resendings ].shift
        ext = info[ :dest_exts ][ dest_id ]

        if ext
          pack = ext[ :wmems ][ pack_id ]

          if pack
            send_pack( tund, pack, info[ :tun_addr ] )
            ext[ :last_traffic_at ] = now
            info[ :last_traffic_at ] = now
            return
          end
        end
      end

      # 若写后到达上限，暂停取写前
      if info[ :dest_exts ].map{ | _, ext | ext[ :wmems ].size }.sum >= WMEMS_LIMIT
        unless info[ :paused ]
          puts "pause #{ tund.object_id } #{ Time.new } p#{ Process.pid }"
          info[ :paused ] = true
        end

        @writes.delete( tund )
        return
      end

      # 取写前
      if info[ :caches ].any?
        dest_id, data = info[ :caches ].shift
      elsif info[ :chunks ].any?
        path = File.join( @tund_chunk_dir, info[ :chunks ].shift )

        begin
          data = IO.binread( path )
          File.delete( path )
        rescue Errno::ENOENT
          add_closing( tund )
          return
        end

        caches = []

        until data.empty?
          dest_id, pack_size = data[ 0, 10 ].unpack( 'Q>n' )
          caches << [ dest_id, data[ 10, pack_size ] ]
          data = data[ ( 10 + pack_size )..-1 ]
        end

        dest_id, data = caches.shift
        info[ :caches ] = caches
      elsif info[ :wbuffs ].any?
        dest_id, data = info[ :wbuffs ].shift
      else
        @writes.delete( tund )
        return
      end

      ext = info[ :dest_exts ][ dest_id ]

      if ext
        pack_id = ext[ :biggest_pack_id ] + 1

        if pack_id == 1
          data = @hex.encode( data )
        end

        pack = "#{ [ dest_id, pack_id ].pack( 'Q>Q>' ) }#{ data }"
        send_pack( tund, pack, info[ :tun_addr ] )
        ext[ :biggest_pack_id ] = pack_id
        ext[ :wmems ][ pack_id ] = pack
        ext[ :send_ats ][ pack_id ] = now
        ext[ :last_traffic_at ] = now
        info[ :last_traffic_at ] = now
      end
    end

    def new_roomd
      roomd = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      roomd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      roomd.bind( Socket.sockaddr_in( @roomd_port, '0.0.0.0' ) )
      roomd_info = {
        tunds: {}  # tund => sockaddr
      }

      @roomd = roomd
      @roomd_info = roomd_info
      @roles[ roomd ] = :roomd
      @infos[ roomd ] = roomd_info
      @reads << roomd
    end

    def loop_expire( tund )
      Thread.new do
        loop do
          sleep 30

          break if tund.closed?

          info = @infos[ tund ]

          if Time.new - info[ :last_traffic_at ] > EXPIRE_AFTER
            @mutex.synchronize do
              @ctlw.write( [ CTL_CLOSE, tund.object_id ].pack( 'CQ>' ) )
            end
          end
        end
      end
    end

    def loop_send_status( tund )
      Thread.new do
        loop do
          sleep STATUS_INTERVAL

          if tund.closed?
            # puts "debug tund is closed, break send status loop #{ Time.new }"
            break
          end

          tund_info = @infos[ tund ]

          if tund_info[ :dest_exts ].any?
            @mutex.synchronize do
              now = Time.new

              tund_info[ :dest_exts ].each do | dest_id, ext |
                if ext[ :last_traffic_at ] && ( now - ext[ :last_traffic_at ] < SEND_STATUS_UNTIL )
                  ctlmsg = [
                    0,
                    DEST_STATUS,
                    dest_id,
                    ext[ :biggest_pack_id ],
                    ext[ :continue_source_pack_id ]
                  ].pack( 'Q>CQ>Q>Q>' )

                  send_pack( tund, ctlmsg, tund_info[ :tun_addr ] )
                end
              end
            end
          end

          if tund_info[ :paused ] && ( tund_info[ :dest_exts ].map{ | _, ext | ext[ :wmems ].size }.sum < RESUME_BELOW )
            @mutex.synchronize do
              @ctlw.write( [ CTL_RESUME, tund.object_id ].pack( 'CQ>' ) )
              tund_info[ :paused ] = false
            end
          end
        end
      end
    end

    def loop_send_fin1( tund, dest_id )
      Thread.new do
        100.times do
          break if tund.closed?

          tund_info = @infos[ tund ]
          break unless tund_info[ :tun_addr ]

          unless tund_info[ :fin1s ].include?( dest_id )
            # puts "debug break send fin1 loop #{ Time.new } p#{ Process.pid }"
            break
          end

          @mutex.synchronize do
            ctlmsg = [
              0,
              FIN1,
              dest_id
            ].pack( 'Q>CQ>' )

            # puts "debug send FIN1 #{ dest_id } #{ Time.new } p#{ Process.pid }"
            send_pack( tund, ctlmsg, tund_info[ :tun_addr ] )
          end

          sleep 1
        end
      end
    end

    def loop_send_fin2( tund, dest_id )
      Thread.new do
        100.times do
          break if tund.closed?

          tund_info = @infos[ tund ]
          break unless tund_info[ :tun_addr ]

          unless tund_info[ :fin2s ].include?( dest_id )
            # puts "debug break send fin2 loop #{ Time.new } p#{ Process.pid }"
            break
          end

          @mutex.synchronize do
            ctlmsg = [
              0,
              FIN2,
              dest_id
            ].pack( 'Q>CQ>' )

            # puts "debug send FIN2 #{ dest_id } #{ Time.new } p#{ Process.pid }"
            send_pack( tund, ctlmsg, tund_info[ :tun_addr ] )
          end

          sleep 1
        end
      end
    end

    def send_pack( sock, pack, target_sockaddr )
      begin
        sock.sendmsg( pack, 0, target_sockaddr )
      rescue IO::WaitWritable, Errno::EINTR => e
        puts "sendmsg #{ e.class } #{ Time.new } p#{ Process.pid }"
      end
    end

    def add_read( sock )
      return if sock.closed? || @reads.include?( sock )

      @reads << sock
    end

    def add_write( sock )
      return if sock.closed? || @writes.include?( sock )

      @writes << sock
    end

    def add_closing( sock )
      return if sock.closed? || @closings.include?( sock )

      @reads.delete( sock )
      @closings << sock
      add_write( sock )
    end

    def close_tund( tund )
      info = close_sock( tund )

      info[ :chunks ].each do | filename |
        begin
          File.delete( File.join( @tund_chunk_dir, filename ) )
        rescue Errno::ENOENT
        end
      end

      info[ :dest_exts ].each{ | _, ext | add_closing( ext[ :dest ] ) }

      @roomd_info[ :tunds ].delete( tund )
    end

    def close_dest( dest )
      info = close_sock( dest )
      tund = info[ :tund ]
      return if tund.closed?

      dest_id = dest.object_id
      tund_info = @infos[ tund ]
      ext = tund_info[ :dest_exts ][ dest_id ]
      return unless ext

      if ext[ :is_source_closed ]
        del_dest_ext( tund_info, dest_id )

        unless tund_info[ :fin2s ].include?( dest_id )
          # puts "debug 2-3. dest.close -> ext.is_source_closed ? yes -> del ext -> loop send fin2 #{ Time.new } p#{ Process.pid }"
          tund_info[ :fin2s ] << dest_id
          loop_send_fin2( tund, dest_id )
        end
      elsif !tund_info[ :fin1s ].include?( dest_id )
        # puts "debug 1-1. dest.close -> ext.is_source_closed ? no -> send fin1 loop #{ Time.new } p#{ Process.pid }"
        tund_info[ :fin1s ] << dest_id
        loop_send_fin1( tund, dest_id )
      end
    end

    def close_sock( sock )
      sock.close
      @reads.delete( sock )
      @writes.delete( sock )
      @closings.delete( sock )
      @socks.delete( sock.object_id )
      @roles.delete( sock )
      @infos.delete( sock )
    end

    def del_dest_ext( tund_info, dest_id )
      ext = tund_info[ :dest_exts ].delete( dest_id )

      if ext
        tund_info[ :source_ids ].delete( ext[ :source_id ] )

        ext[ :chunks ].each do | filename |
          begin
            File.delete( File.join( @dest_chunk_dir, filename ) )
          rescue Errno::ENOENT
          end
        end
      end
    end

  end
end
