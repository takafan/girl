require 'girl/head'
require 'girl/hex'
require 'girl/version'
require 'socket'

##
# Girl::Tun - tcp透明转发，近端。
#
# usage
# =====
#
# Girl::Tund.new( 9090 ).looping # 远端
#
# Girl::Tun.new( 'your.server.ip', 9090, 1919 ).looping # 近端
#
# dig +short www.google.com @127.0.0.1 -p1717 # dig with girl/resolv, got 216.58.217.196
#
# iptables -t nat -A OUTPUT -p tcp -d 216.58.217.196 -j REDIRECT --to-ports 1919
#
# curl https://www.google.com/
#
# 包结构
# ======
#
# 流量打包成udp，在tun-tund之间传输，包结构：
#
# Q>: 1+ source/dest_id -> Q>: pack_id         -> traffic
#     0  ctlmsg         -> C:  1 tund port     -> n: tund port
#                              2 heartbeat     -> C: random char
#                              3 a new source  -> Q>nnN: source_id dst_family dst_port dst_host
#                              4 paired        -> Q>Q>: source_id dest_id
#                              5 dest status   -> Q>Q>Q>: dest_id biggest_dest_pack_id continue_source_pack_id
#                              6 source status -> Q>Q>Q>: source_id biggest_source_pack_id continue_dest_pack_id
#                              7 miss          -> Q>Q>Q>: source/dest_id pack_id_begin pack_id_end
#                              8 fin1          -> Q>: source/dest_id
#                              9 got fin1      -> Q>: source/dest_id
#                             10 fin2          -> Q>: source/dest_id
#                             11 got fin2      -> Q>: source/dest_id
#                             12 tund fin
#                             13 tun fin
#
module Girl
  class Tun
    ##
    # tund_ip          远端ip
    # roomd_port       roomd端口，roomd用于配对tun-tund
    # redir_port       本地端口，请配置iptables把流量引向这个端口
    # source_chunk_dir 文件缓存目录，缓存source写前
    # tun_chunk_dir    文件缓存目录，缓存tun写前
    # hex_block        外部传入自定义加解密
    def initialize( tund_ip, roomd_port = 9090, redir_port = 1919, source_chunk_dir = '/tmp', tun_chunk_dir = '/tmp', hex_block = nil )
      if hex_block
        Girl::Hex.class_eval( hex_block )
      end

      @tund_ip = tund_ip
      @roomd_addr = Socket.sockaddr_in( roomd_port, tund_ip )
      @redir_port = redir_port
      @source_chunk_dir = source_chunk_dir
      @tun_chunk_dir = tun_chunk_dir
      @hex = Girl::Hex.new
      @mutex = Mutex.new
      @reads = []
      @writes = []
      @closings = []
      @roles = {} # sock => :ctlr / :redir / :source / :tun
      @infos = {} # sock => {}
      @socks = {} # sock => sock_id
      @sock_ids = {} # sock_id => sock

      ctlr, ctlw = IO.pipe
      @ctlw = ctlw
      @roles[ ctlr ] = :ctlr
      @reads << ctlr
    end

    def looping
      puts 'looping'

      new_redir
      new_tun

      loop do
        rs, ws = IO.select( @reads, @writes )

        @mutex.synchronize do
          ws.each do | sock |
            case @roles[ sock ]
            when :source
              write_source( sock )
            when :tun
              write_tun( sock )
            end
          end

          rs.each do | sock |
            case @roles[ sock ]
            when :ctlr
              read_ctlr( sock )
            when :redir
              read_redir( sock )
            when :source
              read_source( sock )
            when :tun
              read_tun( sock )
            end
          end
        end
      end
    rescue Interrupt => e
      puts e.class
      quit!
    end

    def quit!
      if @tun && !@tun.closed? && @tun_info[ :tund_addr ]
        ctlmsg = [ 0, TUN_FIN ].pack( 'Q>C' )
        send_pack( @tun, ctlmsg, @tun_info[ :tund_addr ] )
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
        sock = @sock_ids[ sock_id ]

        if sock
          add_closing( sock )
        end
      when CTL_RESUME
        sock_id = ctlr.read( 8 ).unpack( 'Q>' ).first
        sock = @sock_ids[ sock_id ]

        if sock
          add_write( sock )
        end
      end
    end

    ##
    # read redir
    #
    def read_redir( redir )
      begin
        source, addrinfo = redir.accept_nonblock
      rescue IO::WaitReadable, Errno::EINTR => e
        puts "accept source #{ e.class } #{ Time.new } p#{ Process.pid }"
        return
      end

      begin
        # /usr/include/linux/netfilter_ipv4.h
        option = source.getsockopt( Socket::SOL_IP, 80 )
      rescue Exception => e
        puts "get SO_ORIGINAL_DST #{ e.class } #{ Time.new } p#{ Process.pid }"
        source.close
        return
      end

      source_id = @hex.gen_random_num
      @roles[ source ] = :source
      @infos[ source ] = {
        id: source_id,
        tun: @tun
      }
      @socks[ source ] = source_id
      @sock_ids[ source_id ] = source

      @tun_info[ :waitings ][ source_id ] = []
      @tun_info[ :source_exts ][ source_id ] = {
        source: source,
        created_at: Time.new,
        last_recv_at: nil,        # 上一次收到流量的时间
        wbuff: '',                # 写前缓存
        cache: '',                # 块读出缓存
        chunks: [],               # 块队列，写前达到块大小时结一个块 filename
        spring: 0,                # 块后缀，结块时，如果块队列不为空，则自增，为空，则置为0
        wmems: {},                # 写后缓存 pack_id => data
        send_ats: {},             # 上一次发出时间 pack_id => send_at
        biggest_pack_id: 0,       # 发到几
        continue_dest_pack_id: 0, # 收到几
        pieces: {},               # 跳号包 dest_pack_id => data
        is_dest_closed: false,    # 对面是否已关闭
        biggest_dest_pack_id: 0,  # 对面发到几
        completed_pack_id: 0,     # 完成到几（对面收到几）
        last_traffic_at: nil      # 收到有效流量，或者发出流量的时间戳
      }

      add_read( source )
      loop_send_a_new_source( source, option.data )
    end

    ##
    # read source
    #
    def read_source( source )
      begin
        data = source.read_nonblock( PACK_SIZE )
      rescue IO::WaitReadable, Errno::EINTR => e
        return
      rescue Exception => e
        add_closing( source )
        return
      end

      # puts "debug read source #{ data.inspect } #{ Time.new } p#{ Process.pid }"
      info = @infos[ source ]
      tun = info[ :tun ]

      if tun.closed?
        add_closing( source )
        return
      end

      source_id = @socks[ source ]
      tun_info = @infos[ tun ]
      dest_id = tun_info[ :source_ids ][ source_id ]

      if tun_info[ :tund_addr ].nil? || dest_id.nil?
        tun_info[ :waitings ][ source_id ] << data
        return
      end

      tun_info[ :wbuffs ] << [ source_id, data ]

      if tun_info[ :wbuffs ].size >= WBUFFS_LIMIT
        tun_id = @socks[ tun ]
        spring = tun_info[ :chunks ].size > 0 ? ( tun_info[ :spring ] + 1 ) : 0
        filename = "#{ Process.pid }-#{ tun_id }.#{ spring }"
        chunk_path = File.join( @tun_chunk_dir, filename )
        IO.binwrite( chunk_path, tun_info[ :wbuffs ].map{ | source_id, data | "#{ [ source_id, data.bytesize ].pack( 'Q>n' ) }#{ data }" }.join )
        tun_info[ :chunks ] << filename
        tun_info[ :spring ] = spring
        tun_info[ :wbuffs ].clear
      end

      unless tun_info[ :paused ]
        add_write( tun )
      end
    end

    ##
    # read tun
    #
    def read_tun( tun )
      data, addrinfo, rflags, *controls = tun.recvmsg
      sockaddr = addrinfo.to_sockaddr
      now = Time.new
      info = @infos[ tun ]
      dest_id = data[ 0, 8 ].unpack( 'Q>' ).first

      if dest_id == 0
        case data[ 8 ].unpack( 'C' ).first
        when TUND_PORT
          return if sockaddr != @roomd_addr

          unless info[ :tund_addr ]
            tund_port = data[ 9, 2 ].unpack( 'n' ).first
            # puts "debug got TUND_PORT #{ tund_port } #{ Time.new } p#{ Process.pid }"
            info[ :tund_addr ] = Socket.sockaddr_in( tund_port, @tund_ip )
            info[ :last_traffic_at ] = now
            loop_send_heartbeat( tun )
            loop_check_expire( tun )
            loop_send_status( tun )
          end
        when PAIRED
          return if sockaddr != info[ :tund_addr ]

          source_id, dest_id = data[ 9, 16 ].unpack( 'Q>Q>' )
          return unless info[ :source_exts ].include?( source_id )

          return if info[ :source_ids ].include?( source_id )

          # puts "debug got PAIRED #{ source_id } #{ dest_id } #{ Time.new } p#{ Process.pid }"
          info[ :source_ids ][ source_id ] = dest_id
          info[ :dest_ids ][ dest_id ] = source_id
          buffs = info[ :waitings ][ source_id ]

          if buffs.any?
            # puts "debug move #{ buffs.size } waiting buffs to wbuffs #{ Time.new } p#{ Process.pid }"

            buffs.each do | buff |
              info[ :wbuffs ] << [ source_id, buff ]
            end

            buffs.clear
            add_write( tun )
          end
        when DEST_STATUS
          return if sockaddr != info[ :tund_addr ]

          dest_id, biggest_dest_pack_id, continue_source_pack_id  = data[ 9, 24 ].unpack( 'Q>Q>Q>' )
          source_id = info[ :dest_ids ][ dest_id ]
          return unless source_id

          ext = info[ :source_exts ][ source_id ]
          return unless ext

          # 更新对面发到几
          if biggest_dest_pack_id > ext[ :biggest_dest_pack_id ]
            ext[ :biggest_dest_pack_id ] = biggest_dest_pack_id
          end

          # 更新对面收到几，释放写后
          if continue_source_pack_id > ext[ :completed_pack_id ]
            pack_ids = ext[ :wmems ].keys.select { | pack_id | pack_id <= continue_source_pack_id }

            pack_ids.each do | pack_id |
              ext[ :wmems ].delete( pack_id )
              ext[ :send_ats ].delete( pack_id )
            end

            # puts "debug completed #{ continue_source_pack_id }"
            ext[ :completed_pack_id ] = continue_source_pack_id
          end

          if ext[ :is_dest_closed ] && ( ext[ :biggest_dest_pack_id ] == ext[ :continue_dest_pack_id ] )
            add_write( ext[ :source ] )
            return
          end

          # 发miss
          if !ext[ :source ].closed? && ( ext[ :continue_dest_pack_id ] < ext[ :biggest_dest_pack_id ] )
            ranges = []
            curr_pack_id = ext[ :continue_dest_pack_id ] + 1

            ext[ :pieces ].keys.sort.each do | pack_id |
              if pack_id > curr_pack_id
                ranges << [ curr_pack_id, pack_id - 1 ]
              end

              curr_pack_id = pack_id + 1
            end

            if curr_pack_id <= ext[ :biggest_dest_pack_id ]
              ranges << [ curr_pack_id, ext[ :biggest_dest_pack_id ] ]
            end

            pack_count = 0
            # puts "debug #{ ext[ :continue_dest_pack_id ] }/#{ ext[ :biggest_dest_pack_id ] } send MISS #{ ranges.size }"
            ranges.each do | pack_id_begin, pack_id_end |
              if pack_count >= BREAK_SEND_MISS
                puts "break send miss at #{ pack_id_begin } #{ Time.new } p#{ Process.pid }"
                break
              end

              ctlmsg = [
                0,
                MISS,
                dest_id,
                pack_id_begin,
                pack_id_end
              ].pack( 'Q>CQ>Q>Q>' )

              send_pack( tun, ctlmsg,  info[ :tund_addr ] )
              pack_count += ( pack_id_end - pack_id_begin + 1 )
            end
          end
        when MISS
          return if sockaddr != info[ :tund_addr ]

          source_id, pack_id_begin, pack_id_end = data[ 9, 24 ].unpack( 'Q>Q>Q>' )
          ext = info[ :source_exts ][ source_id ]
          return unless ext

          ( pack_id_begin..pack_id_end ).each do | pack_id |
            send_at = ext[ :send_ats ][ pack_id ]

            if send_at
              break if now - send_at < STATUS_INTERVAL

              info[ :resendings ] << [ source_id, pack_id ]
            end
          end

          add_write( tun )
        when FIN1
          return if sockaddr != info[ :tund_addr ]

          # puts "debug 2-1. recv fin1 -> send got_fin1 -> ext.is_dest_closed = true #{ Time.new } p#{ Process.pid }"
          dest_id = data[ 9, 8 ].unpack( 'Q>' ).first
          ctlmsg = [
            0,
            GOT_FIN1,
            dest_id
          ].pack( 'Q>CQ>' )

          send_pack( tun, ctlmsg, info[ :tund_addr ] )

          source_id = info[ :dest_ids ][ dest_id ]
          return unless source_id

          ext = info[ :source_exts ][ source_id ]
          return unless ext

          ext[ :is_dest_closed ] = true
        when GOT_FIN1
          return if sockaddr != info[ :tund_addr ]

          # puts "debug 1-2. recv got_fin1 -> break loop #{ Time.new } p#{ Process.pid }"
          source_id = data[ 9, 8 ].unpack( 'Q>' ).first
          info[ :fin1s ].delete( source_id )
        when FIN2
          return if sockaddr != info[ :tund_addr ]

          # puts "debug 1-3. recv fin2 -> send got_fin2 -> del ext #{ Time.new } p#{ Process.pid }"
          dest_id = data[ 9, 8 ].unpack( 'Q>' ).first
          ctlmsg = [
            0,
            GOT_FIN2,
            dest_id
          ].pack( 'Q>CQ>' )

          send_pack( tun, ctlmsg, info[ :tund_addr ] )

          source_id = info[ :dest_ids ][ dest_id ]
          return unless source_id

          del_source_ext( info, source_id )
        when GOT_FIN2
          return if sockaddr != info[ :tund_addr ]

          # puts "debug 2-4. recv got_fin2 -> break loop #{ Time.new } p#{ Process.pid }"
          source_id = data[ 9, 8 ].unpack( 'Q>' ).first
          info[ :fin2s ].delete( source_id )
        when TUND_FIN
          return if sockaddr != info[ :tund_addr ]

          puts "recv tund fin #{ Time.new } p#{ Process.pid }"
          add_closing( tun )
        end

        return
      end

      return if sockaddr != info[ :tund_addr ]

      source_id = info[ :dest_ids ][ dest_id ]
      return unless source_id

      ext = info[ :source_exts ][ source_id ]
      return if ext.nil? || ext[ :source ].closed?

      pack_id = data[ 8, 8 ].unpack( 'Q>' ).first
      return if ( pack_id <= ext[ :continue_dest_pack_id ] ) || ext[ :pieces ].include?( pack_id )

      data = data[ 16..-1 ]

      # 解混淆
      if pack_id == 1
        data = @hex.decode( data )
      end

      # 放进source的写前缓存，跳号放碎片缓存
      if pack_id - ext[ :continue_dest_pack_id ] == 1
        while ext[ :pieces ].include?( pack_id + 1 )
          data << ext[ :pieces ].delete( pack_id + 1 )
          pack_id += 1
        end

        ext[ :continue_dest_pack_id ] = pack_id
        ext[ :wbuff ] << data

        if ext[ :wbuff ].bytesize >= CHUNK_SIZE
          spring = ext[ :chunks ].size > 0 ? ( ext[ :spring ] + 1 ) : 0
          filename = "#{ Process.pid }-#{ source_id }.#{ spring }"
          chunk_path = File.join( @source_chunk_dir, filename )
          IO.binwrite( chunk_path, ext[ :wbuff ] )
          ext[ :chunks ] << filename
          ext[ :spring ] = spring
          ext[ :wbuff ].clear
        end

        ext[ :last_traffic_at ] = now
        info[ :last_traffic_at ] = now
        add_write( ext[ :source ] )
      else
        ext[ :pieces ][ pack_id ] = data
      end

      ext[ :last_recv_at ] = now
    end

    ##
    # write source
    #
    def write_source( source )
      if @closings.include?( source )
        close_source( source )
        return
      end

      info = @infos[ source ]
      tun = info[ :tun ]

      if tun.closed?
        add_closing( source )
        return
      end

      tun_info = @infos[ tun ]
      source_id = @socks[ source ]
      ext = tun_info[ :source_exts ][ source_id ]

      # 取写前
      data = ext[ :cache ]
      from = :cache

      if data.empty?
        if ext[ :chunks ].any?
          path = File.join( @source_chunk_dir, ext[ :chunks ].shift )

          begin
            data = IO.binread( path )
            File.delete( path )
          rescue Errno::ENOENT
            add_closing( source )
            return
          end
        else
          data = ext[ :wbuff ]
          from = :wbuff
        end
      end

      if data.empty?
        if ext[ :is_dest_closed ] && ( ext[ :biggest_dest_pack_id ] == ext[ :continue_dest_pack_id ] )
          # puts "debug 2-2. all sent && ext.biggest_dest_pack_id == ext.continue_dest_pack_id -> add closing source #{ Time.new } p#{ Process.pid }"
          add_closing( source )
          return
        end

        @writes.delete( source )
        return
      end

      begin
        written = source.write_nonblock( data )
      rescue IO::WaitWritable, Errno::EINTR => e
        ext[ from ] = data
        return
      rescue Exception => e
        add_closing( source )
        return
      end

      data = data[ written..-1 ]
      ext[ from ] = data
    end

    ##
    # write tun
    #
    def write_tun( tun )
      if @closings.include?( tun )
        close_tun( tun )
        new_tun
        return
      end

      now = Time.new
      info = @infos[ tun ]

      # 重传
      while info[ :resendings ].any?
        source_id, pack_id = info[ :resendings ].shift
        ext = info[ :source_exts ][ source_id ]

        if ext
          pack = ext[ :wmems ][ pack_id ]

          if pack
            send_pack( tun, pack, info[ :tund_addr ] )
            ext[ :last_traffic_at ] = now
            info[ :last_traffic_at ] = now
            return
          end
        end
      end

      # 若写后达到上限，暂停取写前
      if info[ :source_exts ].map{ | _, ext | ext[ :wmems ].size }.sum >= WMEMS_LIMIT
        unless info[ :paused ]
          puts "pause #{ @socks[ tun ] } #{ Time.new } p#{ Process.pid }"
          info[ :paused ] = true
        end

        @writes.delete( tun )
        return
      end

      # 取写前
      if info[ :caches ].any?
        source_id, data = info[ :caches ].shift
      elsif info[ :chunks ].any?
        path = File.join( @tun_chunk_dir, info[ :chunks ].shift )

        begin
          data = IO.binread( path )
          File.delete( path )
        rescue Errno::ENOENT
          add_closing( tun )
          return
        end

        caches = []

        until data.empty?
          source_id, pack_size = data[ 0, 10 ].unpack( 'Q>n' )
          caches << [ source_id, data[ 10, pack_size ] ]
          data = data[ ( 10 + pack_size )..-1 ]
        end

        source_id, data = caches.shift
        info[ :caches ] = caches
      elsif info[ :wbuffs ].any?
        source_id, data = info[ :wbuffs ].shift
      else
        @writes.delete( tun )
        return
      end

      ext = info[ :source_exts ][ source_id ]

      if ext
        pack_id = ext[ :biggest_pack_id ] + 1

        if pack_id == 1
          data = @hex.encode( data )
        end

        pack = "#{ [ source_id, pack_id ].pack( 'Q>Q>' ) }#{ data }"
        send_pack( tun, pack, info[ :tund_addr ] )
        ext[ :biggest_pack_id ] = pack_id
        ext[ :wmems ][ pack_id ] = pack
        ext[ :send_ats ][ pack_id ] = now
        ext[ :last_traffic_at ] = now
        info[ :last_traffic_at ] = now
      end
    end

    def new_redir
      redir = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      redir.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
      redir.bind( Socket.sockaddr_in( @redir_port, '0.0.0.0' ) )
      redir.listen( 511 )

      @roles[ redir ] = :redir
      @reads << redir
    end

    def new_tun
      tun = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      tun.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )
      tun_id = @hex.gen_random_num
      tun_info = {
        id: tun_id,
        waitings: {},        # 还没连上tund，或者还没配上dest，暂存流量 source_id => buffs[]
        wbuffs: [],          # 写前缓存 [ source_id, data ]
        caches: [],          # 块读出缓存 [ source_id, data ]
        chunks: [],          # 块队列 filename
        spring: 0,           # 块后缀，结块时，如果块队列不为空，则自增，为空，则置为0
        tund_addr: nil,      # 远端地址
        source_exts: {},     # 长命信息 source_id => {}
        source_ids: {},      # source_id => dest_id
        dest_ids: {},        # dest_id => source_id
        fin1s: [],           # fin1: source已关闭，等待对面收完流量 source_id
        fin2s: [],           # fin2: 流量已收完 source_id
        paused: false,       # 是否暂停写
        resendings: [],      # 重传队列 [ source_id, pack_id ]
        last_traffic_at: nil # 收到有效流量，或者发出流量的时间戳
      }

      @tun = tun
      @tun_info = tun_info
      @roles[ tun ] = :tun
      @infos[ tun ] = tun_info
      @socks[ tun ] = tun_id
      @sock_ids[ tun_id ] = tun

      send_pack( tun, @hex.hello, @roomd_addr )
      add_read( tun )
      check_expire( tun )
    end

    def check_expire( tun )
      Thread.new do
        sleep 3

        @mutex.synchronize do
          unless tun.closed?
            tun_info = @infos[ tun ]

            unless tun_info[ :tund_addr ]
              tun_id = @socks[ tun ]
              @ctlw.write( [ CTL_CLOSE, tun_id ].pack( 'CQ>' ) )
            end
          end
        end
      end
    end

    def loop_send_heartbeat( tun )
      Thread.new do
        loop do
          @mutex.synchronize do
            break if tun.closed?
            send_heartbeat( tun )
          end

          sleep HEARTBEAT_INTERVAL
        end
      end
    end

    def loop_check_expire( tun )
      Thread.new do
        loop do
          sleep CHECK_EXPIRE_INTERVAL

          @mutex.synchronize do
            break if tun.closed?

            now = Time.new
            tun_info = @infos[ tun ]

            if now - tun_info[ :last_traffic_at ] > EXPIRE_AFTER
              tun_id = @socks[ tun ]
              # puts "debug ctlw close tun #{ tun_id } #{ Time.new } p#{ Process.pid }"
              @ctlw.write( [ CTL_CLOSE, tun_id ].pack( 'CQ>' ) )
              break
            end

            exts = tun_info[ :source_exts ].select{ | _, ext | now - ext[ :created_at ] > 5 }

            if exts.any?
              exts.each do | source_id, ext |
                if ext[ :last_recv_at ].nil? || ( now - ext[ :last_recv_at ] > EXPIRE_AFTER )
                  # puts "debug ctlw close source #{ source_id } #{ Time.new } p#{ Process.pid }"
                  @ctlw.write( [ CTL_CLOSE, source_id ].pack( 'CQ>' ) )
                end
              end
            end
          end
        end
      end
    end

    def loop_send_status( tun )
      Thread.new do
        loop do
          sleep STATUS_INTERVAL

          @mutex.synchronize do
            if tun.closed?
              # puts "debug tun is closed, break send status loop #{ Time.new }"
              break
            end

            tun_info = @infos[ tun ]

            if tun_info[ :source_exts ].any?
              now = Time.new

              tun_info[ :source_exts ].each do | source_id, ext |
                if ext[ :last_traffic_at ] && ( now - ext[ :last_traffic_at ] < SEND_STATUS_UNTIL )
                  ctlmsg = [
                    0,
                    SOURCE_STATUS,
                    source_id,
                    ext[ :biggest_pack_id ],
                    ext[ :continue_dest_pack_id ]
                  ].pack( 'Q>CQ>Q>Q>' )

                  send_pack( tun, ctlmsg, tun_info[ :tund_addr ] )
                end
              end
            end

            if tun_info[ :paused ] && ( tun_info[ :source_exts ].map{ | _, ext | ext[ :wmems ].size }.sum < RESUME_BELOW )
              tun_id = @socks[ tun ]
              puts "ctlw resume #{ tun_id } #{ Time.new } p#{ Process.pid }"
              @ctlw.write( [ CTL_RESUME, tun_id ].pack( 'CQ>' ) )
              tun_info[ :paused ] = false
            end
          end
        end
      end
    end

    def loop_send_a_new_source( source, original_dst )
      Thread.new do
        30.times do
          @mutex.synchronize do
            break if source.closed?

            source_info = @infos[ source ]
            tun = source_info[ :tun ]
            break if tun.closed?

            tun_info = @infos[ tun ]

            if tun_info[ :tund_addr ]
              source_id = @socks[ source ]
              dest_id = tun_info[ :source_ids ][ source_id ]

              if dest_id
                # puts "debug break a new source loop #{ Time.new } p#{ Process.pid }"
                break
              end

              ctlmsg = "#{ [ 0, A_NEW_SOURCE, source_id ].pack( 'Q>CQ>' ) }#{ original_dst }"
              # puts "debug send a new source #{ Time.new } p#{ Process.pid }"
              send_pack( tun, ctlmsg, tun_info[ :tund_addr ] )
            end
          end

          sleep 1
        end
      end
    end

    def loop_send_fin1( tun, source_id )
      Thread.new do
        30.times do
          @mutex.synchronize do
            break if tun.closed?

            tun_info = @infos[ tun ]
            break unless tun_info[ :tund_addr ]

            unless tun_info[ :fin1s ].include?( source_id )
              # puts "debug break send fin1 loop #{ Time.new } p#{ Process.pid }"
              break
            end

            ctlmsg = [
              0,
              FIN1,
              source_id
            ].pack( 'Q>CQ>' )

            # puts "debug send FIN1 #{ source_id } #{ Time.new } p#{ Process.pid }"
            send_pack( tun, ctlmsg, tun_info[ :tund_addr ] )
          end

          sleep 1
        end
      end
    end

    def loop_send_fin2( tun, source_id )
      Thread.new do
        30.times do
          @mutex.synchronize do
            break if tun.closed?

            tun_info = @infos[ tun ]
            break unless tun_info[ :tund_addr ]

            unless tun_info[ :fin2s ].include?( source_id )
              # puts "debug break send fin2 loop #{ Time.new } p#{ Process.pid }"
              break
            end

            ctlmsg = [
              0,
              FIN2,
              source_id
            ].pack( 'Q>CQ>' )

            # puts "debug send FIN2 #{ source_id } #{ Time.new } p#{ Process.pid }"
            send_pack( tun, ctlmsg, tun_info[ :tund_addr ] )
          end

          sleep 1
        end
      end
    end

    def send_heartbeat( tun )
      info = @infos[ tun ]
      ctlmsg = [ 0, HEARTBEAT, rand( 128 ) ].pack( 'Q>CC' )
      send_pack( tun, ctlmsg, info[ :tund_addr ] )
    end

    def send_pack( sock, data, target_sockaddr )
      begin
        sock.sendmsg( data, 0, target_sockaddr )
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

    def close_tun( tun )
      info = close_sock( tun )

      info[ :chunks ].each do | filename |
        begin
          File.delete( File.join( @tun_chunk_dir, filename ) )
        rescue Errno::ENOENT
        end
      end

      info[ :source_exts ].each{ | _, ext | add_closing( ext[ :source ] ) }
    end

    def close_source( source )
      info = close_sock( source )
      tun = info[ :tun ]
      return if tun.closed?

      source_id = info[ :id ]
      tun_info = @infos[ tun ]
      ext = tun_info[ :source_exts ][ source_id ]
      return unless ext

      if ext[ :is_dest_closed ]
        del_source_ext( tun_info, source_id )

        unless tun_info[ :fin2s ].include?( source_id )
          # puts "debug 2-3. source.close -> ext.is_dest_closed ? yes -> del ext -> loop send fin2 #{ Time.new } p#{ Process.pid }"
          tun_info[ :fin2s ] << source_id
          loop_send_fin2( tun, source_id )
        end
      elsif !tun_info[ :fin1s ].include?( source_id )
        # puts "debug 1-1. source.close -> ext.is_dest_closed ? no -> send fin1 loop #{ Time.new } p#{ Process.pid }"
        tun_info[ :fin1s ] << source_id
        loop_send_fin1( tun, source_id )
      end
    end

    def close_sock( sock )
      sock.close
      @reads.delete( sock )
      @writes.delete( sock )
      @closings.delete( sock )
      @roles.delete( sock )
      info = @infos.delete( sock )
      sock_id = @socks.delete( sock )
      @sock_ids.delete( sock_id )

      info
    end

    def del_source_ext( tun_info, source_id )
      tun_info[ :waitings ].delete( source_id )
      ext = tun_info[ :source_exts ].delete( source_id )

      if ext
        ext[ :chunks ].each do | filename |
          begin
            File.delete( File.join( @source_chunk_dir, filename ) )
          rescue Errno::ENOENT
          end
        end
      end

      dest_id = tun_info[ :source_ids ].delete( source_id )

      if dest_id
        tun_info[ :dest_ids ].delete( dest_id )
      end
    end

  end
end
