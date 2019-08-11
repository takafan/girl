require 'girl/head'
require 'girl/hex'
require 'girl/version'
require 'socket'

##
# Girl::Tund - tcp流量正常的到达目的地。远端。
#
##
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
      @dest_chunk_dir = dest_chunk_dir
      @tund_chunk_dir = tund_chunk_dir
      @hex = Girl::Hex.new
      @mutex = Mutex.new
      @reads = []
      @writes = []
      @closings = []
      @socks = {} # object_id => sock
      @roles = {} # sock => :ctlr / :roomd / :dest / :tund
      @infos = {}

      ctlr, ctlw = IO.pipe
      @ctlw = ctlw
      @roles[ ctlr ] = :ctlr
      @reads << ctlr

      roomd = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      roomd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      roomd.bind( Socket.sockaddr_in( roomd_port, '0.0.0.0' ) )
      roomd_info = {
        tunds: [],        # tund
        paused_tunds: [], # 暂停写的tunds
        tund_clients: {}, # tund => sockaddr
        wmems_size: 0     # 写后缓存总个数
      }

      @roomd = roomd
      @roomd_info = roomd_info
      @roles[ roomd ] = :roomd
      @infos[ roomd ] = roomd_info
      @reads << roomd
    end

    def looping
      puts 'looping'

      loop_expire
      loop_send_status

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

      @roomd_info[ :tunds ].each do | tund |
        unless tund.closed?
          tund_info = @infos[ tund ]

          if tund_info[ :tun_addr ]
            send_pack( tund, ctlmsg, tund_info[ :tun_addr ] )
          end
        end
      end

      exit
    end

    private

    ##
    # read ctlr
    #
    def read_ctlr( ctlr )
      case ctlr.read( 1 )
      when CTL_CLOSE_SOCK
        sock_id = ctlr.read( 8 ).unpack( 'Q>' ).first
        sock = @socks[ sock_id ]

        if sock
          add_closing( sock )
        end
      when CTL_RESUME
        len = ctlr.read( 2 ).unpack( 'n' ).first
        tund_ids = ctlr.read( 8 * len ).unpack( 'Q>*' )
        tund_ids.each do | tund_id |
          puts "resume #{ tund_id } #{ Time.new } p#{ Process.pid }"
          tund = @socks[ tund_id ]

          if tund
            add_write( tund )
          end
        end
      end
    end

    ##
    # read roomd
    #
    def read_roomd( roomd )
      info = @infos[ roomd ]
      data, addrinfo, rflags, *controls = roomd.recvmsg
      sockaddr = addrinfo.to_sockaddr
      return if info[ :tund_clients ].any? { | tund, client | client == sockaddr }

      result = @hex.check( data, addrinfo )

      if result != :success
        puts "#{ result } #{ Time.new } p#{ Process.pid }"
        return
      end

      tund = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      tund.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )
      tund_id = tund.object_id

      @socks[ tund_id ] = tund
      @roles[ tund ] = :tund
      @infos[ tund ] = {
        wbuff: '',                                      # 写前缓存
        cache: '',                                      # 块读出缓存
        filename: [ Process.pid, tund_id ].join( '-' ), # 块名
        chunk_dir: @tund_chunk_dir,                     # 块目录
        chunks: [],                                     # 块文件名，wbuff每超过1.4M落一个块
        chunk_seed: 0,                                  # 块序号
        tun_addr: nil,                                  # 近端地址
        src_dst: {},                                    # source_id => dest_id
        dests: [],                                      # 开着的dest
        dest_exts: {},                                  # 传输相关 dest_id => {}
        fin1s: [],                                      # fin1: dest已关闭，等待对面收完流量 dest_id
        fin2s: [],                                      # fin2: 流量已收完 dest_id
        last_coming_at: nil                             # 上一次来流量的时间
      }

      info[ :tunds ] << tund
      puts "tunds size #{ info[ :tunds ].size } #{ Time.new } p#{ Process.pid }"
      info[ :tund_clients ][ tund ] = sockaddr

      add_read( tund )
      loop_send_tund_port( tund, sockaddr )
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

      pack_id = info[ :pcur ] + 1

      if pack_id == 1
        data = @hex.encode( data )
      end

      prefix = [ data.bytesize, dest.object_id, pack_id ].pack( 'nQ>Q>' )
      is_add_write = !@roomd_info[ :paused_tunds ].include?( tund )
      add_buff( tund, [ prefix, data ].join, is_add_write )
      info[ :pcur ] = pack_id
    end

    ##
    # read tund
    #
    def read_tund( tund )
      info = @infos[ tund ]
      data, addrinfo, rflags, *controls = tund.recvmsg
      tun_addr = addrinfo.to_sockaddr

      if info[ :tun_addr ].nil?
        info[ :tun_addr ] = tun_addr
        add_write( tund )
      elsif info[ :tun_addr ] != tun_addr
        puts "tun addr not match? #{ addrinfo.ip_unpack.inspect } #{ Time.new } p#{ Process.pid }"
        return
      end

      info[ :last_coming_at ] = Time.new
      source_id = data[ 0, 8 ].unpack( 'Q>' ).first

      if source_id == 0
        ctl_num = data[ 8 ].unpack( 'C' ).first

        case ctl_num
        when A_NEW_SOURCE
          source_id = data[ 9, 8 ].unpack( 'Q>' ).first
          dest_id = info[ :src_dst ][ source_id ]

          if dest_id
            send_paired( tund, source_id, dest_id )
            return
          end

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
            wbuff: '',
            cache: '',
            filename: [ Process.pid, dest_id ].join( '-' ),
            chunk_dir: @dest_chunk_dir,
            chunks: [],
            chunk_seed: 0,
            pcur: 0, # 打包光标
            tund: tund
          }

          info[ :dests ] << dest
          info[ :dest_exts ][ dest_id ] = {
            dest: dest,
            wmems: {},                   # 写后缓存 pack_id => [ data, add_at ]
            biggest_pack_id: 0,          # 发到几
            continue_source_pack_id: 0,  # 收到几
            pieces: {},                  # 跳号包 source_pack_id => data
            source_id: source_id,        # 对面id
            is_source_closed: false,     # 对面是否已关闭
            biggest_source_pack_id: 0,   # 对面发到几
            completed_pack_id: 0         # 完成到几（对面收到几）
          }
          info[ :src_dst ][ source_id ] = dest_id
          add_read( dest )
          send_paired( tund, source_id, dest_id )
        when SOURCE_STATUS
          source_id, biggest_source_pack_id, continue_dest_pack_id  = data[ 9, 24 ].unpack( 'Q>Q>Q>' )
          dest_id = info[ :src_dst ][ source_id ]
          return unless dest_id

          ext = info[ :dest_exts ][ dest_id ]
          return unless ext

          # 更新对面发到几
          if biggest_source_pack_id > ext[ :biggest_source_pack_id ]
            ext[ :biggest_source_pack_id ] = biggest_source_pack_id
          end

          # 更新对面收到几，释放写后
          if continue_dest_pack_id > ext[ :completed_pack_id ]
            wmems = ext[ :wmems ]
            pack_ids = wmems.keys.select { | pack_id | pack_id <= continue_dest_pack_id }
            pack_ids.each { | pack_id | wmems.delete( pack_id ) }
            @roomd_info[ :wmems_size ] -= pack_ids.size
            # puts "debug completed #{ continue_dest_pack_id } wmems #{ @roomd_info[ :wmems_size ] }"
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
            data, add_at = ext[ :wmems ][ pack_id ]
            break if Time.new - add_at < STATUS_INTERVAL

            if data
              send_pack( tund, data, info[ :tun_addr ] )
            end
          end
        when FIN1
          # > 2-1. recv fin1 -> send got_fin1 -> ext.is_source_closed = true
          #   2-2. all sent && ext.biggest_source_pack_id == ext.continue_source_pack_id -> add closing dest
          #   2-3. dest.close -> ext.is_source_closed ? yes -> del ext -> loop send fin2
          #   2-4. recv got_fin2 -> break loop

          # puts "debug 2-1. recv fin1 -> send got_fin1 -> ext.is_source_closed = true #{ Time.new } p#{ Process.pid }"
          source_id = data[ 9, 8 ].unpack( 'Q>' ).first
          ctlmsg = [
            0,
            GOT_FIN1,
            source_id
          ].pack( 'Q>CQ>' )

          send_pack( tund, ctlmsg, info[ :tun_addr ] )

          dest_id = info[ :src_dst ][ source_id ]
          return unless dest_id

          ext = info[ :dest_exts ][ dest_id ]
          return unless ext

          ext[ :is_source_closed ] = true
        when GOT_FIN1
          #   1-1. dest.close -> ext.is_source_closed ? no -> send fin1 loop
          # > 1-2. recv got_fin1 -> break loop
          #   1-3. recv fin2 -> send got_fin2 -> del ext

          # puts "debug 1-2. recv got_fin1 -> break loop #{ Time.new } p#{ Process.pid }"
          dest_id = data[ 9, 8 ].unpack( 'Q>' ).first
          info[ :fin1s ].delete( dest_id )
        when FIN2
          #   1-1. dest.close -> ext.is_source_closed ? no -> send fin1 loop
          #   1-2. recv got_fin1 -> break loop
          # > 1-3. recv fin2 -> send got_fin2 -> del ext

          # puts "debug 1-3. recv fin2 -> send got_fin2 -> del ext #{ Time.new } p#{ Process.pid }"
          source_id = data[ 9, 8 ].unpack( 'Q>' ).first
          ctlmsg = [
            0,
            GOT_FIN2,
            source_id
          ].pack( 'Q>CQ>' )

          send_pack( tund, ctlmsg, info[ :tun_addr ] )

          dest_id = info[ :src_dst ].delete( source_id )
          return unless dest_id

          del_dest_ext( tund, dest_id )
        when GOT_FIN2
          #   2-1. recv fin1 -> send got_fin1 -> ext.is_source_closed = true
          #   2-2. all sent && ext.biggest_source_pack_id == ext.continue_source_pack_id -> add closing dest
          #   2-3. dest.close -> ext.is_source_closed ? yes -> del ext -> loop send fin2
          # > 2-4. recv got_fin2 -> break loop

          # puts "debug 2-4. recv got_fin2 -> break loop #{ Time.new } p#{ Process.pid }"
          dest_id = data[ 9, 8 ].unpack( 'Q>' ).first
          info[ :fin2s ].delete( dest_id )
        when TUN_FIN
          puts "tun fin #{ Time.new } p#{ Process.pid }"
          add_closing( tund )
        end

        return
      end

      dest_id = info[ :src_dst ][ source_id ]
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
        add_buff( ext[ :dest ], data )
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
      data, from = get_buff( dest )

      if data.empty?
        tund = info[ :tund ]

        if tund.closed?
          add_closing( dest )
          return
        end

        tund_info = @infos[ tund ]
        ext = tund_info[ :dest_exts ][ dest.object_id ]

        #   2-1. recv fin1 -> send got_fin1 -> ext.is_source_closed = true
        # > 2-2. all sent && ext.biggest_source_pack_id == ext.continue_source_pack_id -> add closing dest
        #   2-3. dest.close -> ext.is_source_closed ? yes -> del ext -> loop send fin2
        #   2-4. recv got_fin2 -> break loop
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
        return
      rescue Exception => e
        add_closing( dest )
        return
      end

      data = data[ written..-1 ]
      info[ from ] = data
    end

    ##
    # write tund
    #
    def write_tund( tund )
      if @closings.include?( tund )
        close_tund( tund )
        return
      end

      if @roomd_info[ :wmems_size ] > WMEMS_LIMIT
        unless @roomd_info[ :paused_tunds ].include?( tund )
          puts "pause #{ tund.object_id } #{ Time.new } p#{ Process.pid }"
          @roomd_info[ :paused_tunds ] << tund
        end

        @writes.delete( tund )
        return
      end

      data, from = get_buff( tund )

      if data.empty?
        @writes.delete( tund )
        return
      end

      info = @infos[ tund ]
      len = data[ 0, 2 ].unpack( 'n' ).first
      pack = data[ 2, ( 16 + len ) ]
      dest_id, pack_id = pack[ 0, 16 ].unpack( 'Q>Q>' )
      ext = info[ :dest_exts ][ dest_id ]

      if ext
        send_pack( tund, pack, info[ :tun_addr ] )
        ext[ :biggest_pack_id ] = pack_id
        ext[ :wmems ][ pack_id ] = [ pack, Time.new ]
        @roomd_info[ :wmems_size ] += 1
      end

      data = data[ ( 18 + len )..-1 ]
      info[ from ] = data
    end

    def loop_expire
      Thread.new do
        loop do
          sleep CHECK_EXPIRE_INTERVAL

          if @roomd_info[ :tunds ].any?
            @mutex.synchronize do
              now = Time.new

              @roomd_info[ :tunds ].each do | tund |
                unless tund.closed?
                  info = @infos[ tund ]

                  if info[ :last_coming_at ] && ( now - info[ :last_coming_at ] > EXPIRE_AFTER )
                    @ctlw.write( [ CTL_CLOSE_SOCK, [ tund.object_id ].pack( 'Q>' ) ].join )
                  end
                end
              end
            end
          end
        end
      end
    end

    def loop_send_status
      Thread.new do
        loop do
          sleep STATUS_INTERVAL

          if @roomd_info[ :tunds ].any?
            @mutex.synchronize do
              @roomd_info[ :tunds ].each do | tund |
                unless tund.closed?
                  tund_info = @infos[ tund ]

                  if tund_info[ :tun_addr ] && tund_info[ :dest_exts ].any?
                    tund_info[ :dest_exts ].each do | dest_id, ext |
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
            end
          end

          if @roomd_info[ :paused_tunds ].any? && ( @roomd_info[ :wmems_size ].size < RESUME_BELOW )
            @mutex.synchronize do
              tund_ids = @roomd_info[ :paused_tunds ].map { | tund | tund.object_id }
              puts "resume #{ Time.new } p#{ Process.pid }"
              @ctlw.write( [ CTL_RESUME, [ tund_ids.size ].pack( 'n' ), tund_ids.pack( 'Q>*' ) ].join )
              @roomd_info[ :paused_tunds ].clear
            end
          end
        end
      end
    end

    def loop_send_tund_port( tund, client )
      tund_port = tund.local_address.ip_unpack.last

      Thread.new do
        100.times do
          break if tund.closed?

          tund_info = @infos[ tund ]

          if tund_info[ :tun_addr ]
            # puts "debug break send tund port loop #{ Time.new } p#{ Process.pid }"
            break
          end

          @mutex.synchronize do
            ctlmsg = [
              0,
              TUND_PORT,
              tund_port
            ].pack( 'Q>Cn' )
            # puts "debug send TUND_PORT #{ tund_port } #{ Time.new } p#{ Process.pid }"
            send_pack( @roomd, ctlmsg, client )
          end

          sleep 1
        end
      end
    end

    def loop_send_fin1( tund, dest_id )
      Thread.new do
        100.times do
          break if tund.closed?

          tund_info = @infos[ tund ]

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

    def send_paired( tund, source_id, dest_id )
      return if tund.closed?

      tund_info = @infos[ tund ]
      return unless tund_info[ :tun_addr ]

      ctlmsg = [
        0,
        PAIRED,
        source_id,
        dest_id
      ].pack( 'Q>CQ>Q>' )

      # puts "debug send PAIRED #{ source_id } #{ dest_id } #{ Time.new } p#{ Process.pid }"
      send_pack( tund, ctlmsg, tund_info[ :tun_addr ] )
    end

    def send_pack( sock, pack, target_sockaddr )
      begin
        sock.sendmsg( pack, 0, target_sockaddr )
      rescue IO::WaitWritable, Errno::EINTR => e
        puts "sendmsg #{ e.class } #{ Time.new } p#{ Process.pid }"
      end
    end

    def get_buff( sock )
      info = @infos[ sock ]
      data, from = info[ :cache ], :cache

      if data.empty?
        if info[ :chunks ].any?
          path = File.join( info[ :chunk_dir ], info[ :chunks ].shift )
          data = info[ :cache ] = IO.binread( path )

          begin
            File.delete( path )
          rescue Errno::ENOENT
          end
        else
          data, from = info[ :wbuff ], :wbuff
        end
      end

      [ data, from ]
    end

    def add_buff( sock, data, is_add_write = true )
      info = @infos[ sock ]
      info[ :wbuff ] << data

      if info[ :wbuff ].size >= CHUNK_SIZE
        filename = [ info[ :filename ], info[ :chunk_seed ] ].join( '.' )
        chunk_path = File.join( info[ :chunk_dir ], filename )
        IO.binwrite( chunk_path, info[ :wbuff ] )
        info[ :chunks ] << filename
        info[ :chunk_seed ] += 1
        info[ :wbuff ].clear
      end

      if is_add_write
        add_write( sock )
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

    def del_dest_ext( tund, dest_id )
      tund_info = @infos[ tund ]
      ext = tund_info[ :dest_exts ].delete( dest_id )
      return if ext.nil? || ext[ :wmems ].empty?

      @roomd_info[ :wmems_size ] -= ext[ :wmems ].size
      # puts "debug delete ext, wmems #{ @roomd_info[ :wmems_size ] } #{ Time.new } p#{ Process.pid }"
    end

    def close_tund( tund )
      info = close_sock( tund )
      info[ :dests ].each { | dest | add_closing( dest ) }
      info[ :dest_exts ].each { | _, ext | @roomd_info[ :wmems_size ] -= ext[ :wmems ].size }
      @roomd_info[ :tunds ].delete( tund )
      @roomd_info[ :paused_tunds ].delete( tund )
      @roomd_info[ :tund_clients ].delete( tund )
    end

    def close_dest( dest )
      info = close_sock( dest )
      tund = info[ :tund ]
      return if tund.closed?

      tund_info = @infos[ tund ]
      tund_info[ :dests ].delete( dest )
      dest_id = dest.object_id
      ext = tund_info[ :dest_exts ][ dest_id ]

      if ext
        ext[ :pieces ].clear

        if ext[ :is_source_closed ]
          #   2-1. recv fin1 -> send got_fin1 -> ext.is_source_closed = true
          #   2-2. all sent && ext.biggest_source_pack_id == ext.continue_source_pack_id -> add closing dest
          # > 2-3. dest.close -> ext.is_source_closed ? yes -> del ext -> loop send fin2
          #   2-4. recv got_fin2 -> break loop

          # puts "debug 2-3. dest.close -> ext.is_source_closed ? yes -> del ext -> loop send fin2 #{ Time.new } p#{ Process.pid }"
          tund_info[ :src_dst ].delete( ext[ :source_id ] )
          del_dest_ext( tund, dest_id )

          unless tund_info[ :fin2s ].include?( dest_id )
            tund_info[ :fin2s ] << dest_id
            loop_send_fin2( tund, dest_id )
          end
        else
          # > 1-1. dest.close -> ext.is_source_closed ? no -> send fin1 loop
          #   1-2. recv got_fin1 -> break loop
          #   1-3. recv fin2 -> send got_fin2 -> del ext

          # puts "debug 1-1. dest.close -> ext.is_source_closed ? no -> send fin1 loop #{ Time.new } p#{ Process.pid }"
          unless tund_info[ :fin1s ].include?( dest_id )
            tund_info[ :fin1s ] << dest_id
            loop_send_fin1( tund, dest_id )
          end
        end
      end
    end

    def close_sock( sock )
      sock.close
      @reads.delete( sock )
      @writes.delete( sock )
      @closings.delete( sock )
      @socks.delete( sock.object_id )
      @roles.delete( sock )
      info = @infos.delete( sock )

      if info
        info[ :chunks ].each do | filename |
          begin
            File.delete( File.join( info[ :chunk_dir ], filename ) )
          rescue Errno::ENOENT
          end
        end
      end

      info
    end
  end
end
