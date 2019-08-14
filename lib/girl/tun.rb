require 'girl/head'
require 'girl/hex'
require 'girl/version'
require 'socket'

##
# Girl::Tun - tcp流量正常的到达目的地。近端。
#
##
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
# 两套关闭
# ========
#
# 1-1. source.close -> ext.is_dest_closed ? no -> send fin1 loop
# 1-2. recv got_fin1 -> break loop
# 1-3. recv fin2 -> send got_fin2 -> del ext
#
# 2-1. recv fin1 -> send got_fin1 -> ext.is_dest_closed = true
# 2-2. all sent && ext.biggest_dest_pack_id == ext.continue_dest_pack_id -> add closing source
# 2-3. source.close -> ext.is_dest_closed ? yes -> del ext -> loop send fin2
# 2-4. recv got_fin2 -> break loop
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
      @source_chunk_dir = source_chunk_dir
      @tun_chunk_dir = tun_chunk_dir
      @hex = Girl::Hex.new
      @mutex = Mutex.new
      @reads = []
      @writes = []
      @closings = []
      @socks = {} # object_id => sock
      @roles = {} # sock => :ctlr / :redir / :source / :tun
      @infos = {}

      ctlr, ctlw = IO.pipe
      @ctlw = ctlw
      @roles[ ctlr ] = :ctlr
      @reads << ctlr

      redir = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      redir.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
      redir.bind( Socket.sockaddr_in( redir_port, '0.0.0.0' ) )
      redir.listen( 511 )
      @roles[ redir ] = :redir
      @reads << redir

      new_tun
    end

    def looping
      puts 'looping'

      loop_expire
      loop_send_heartbeat
      loop_send_status

      loop do
        rs, ws = IO.select( @reads, @writes )

        @mutex.synchronize do
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

          ws.each do | sock |
            case @roles[ sock ]
            when :source
              write_source( sock )
            when :tun
              write_tun( sock )
            end
          end
        end
      end
    rescue Interrupt => e
      puts e.class
      quit!
    end

    def quit!
      if !@tun.closed? && @tun_info[ :tund_addr ]
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
      case ctlr.read( 1 )
      when CTL_CLOSE_SOCK
        sock_id = ctlr.read( 8 ).unpack( 'Q>' ).first
        sock = @socks[ sock_id ]

        if sock
          puts "expire tun #{ Time.new } p#{ Process.pid }"
          add_closing( sock )
        end
      when CTL_RESUME
        puts "resume tun #{ Time.new } p#{ Process.pid }"
        add_write( @tun )
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

      source_id = source.object_id

      @socks[ source_id ] = source
      @roles[ source ] = :source
      @infos[ source ] = {
        wbuff: '',
        cache: '',
        filename: [ Process.pid, source_id ].join( '-' ),
        chunk_dir: @source_chunk_dir,
        chunks: [],
        chunk_seed: 0,
        pcur: 0
      }
      @tun_info[ :sources ] << source
      @tun_info[ :source_exts ][ source_id ] = {
        source: source,
        wmems: {},                 # 写后缓存 pack_id => [ data, add_at ]
        biggest_pack_id: 0,        # 发到几
        continue_dest_pack_id: 0,  # 收到几
        pieces: {},                # 跳号包 dest_pack_id => data
        dest_id: nil,              # 对面id
        is_dest_closed: false,     # 对面是否已关闭
        biggest_dest_pack_id: 0,   # 对面发到几
        completed_pack_id: 0,      # 完成到几（对面收到几）
        last_traffic_at: nil       # 有流量发出，或者有更新收到几，时间戳
      }

      add_read( source )
      loop_send_a_new_source( source_id, option.data )
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
      pack_id = info[ :pcur ] + 1

      # ssh的第一段流量是明文版本号，https的第一段流量含明文域名，如果需要，混淆它。
      # 覆盖encode方法自定义混淆。
      if pack_id == 1
        data = @hex.encode( data )
      end

      prefix = [ data.bytesize, source.object_id, pack_id ].pack( 'nQ>Q>' )
      is_add_write = @tun_info[ :tund_addr ] && !@tun_info[ :paused ]
      add_buff( @tun, [ prefix, data ].join, is_add_write )
      info[ :pcur ] = pack_id
    end

    ##
    # read tun
    #
    def read_tun( tun )
      info = @infos[ tun ]
      data, addrinfo, rflags, *controls = tun.recvmsg
      now = Time.new
      info[ :last_coming_at ] = now
      dest_id = data[ 0, 8 ].unpack( 'Q>' ).first

      if dest_id == 0
        case data[ 8 ].unpack( 'C' ).first
        when TUND_PORT
          tund_port = data[ 9, 2 ].unpack( 'n' ).first
          # puts "debug got TUND_PORT #{ tund_port } #{ Time.new } p#{ Process.pid }"

          info[ :tund_addr ] = Socket.sockaddr_in( tund_port, @tund_ip )
          send_heartbeat
          add_write( tun )
        when PAIRED
          source_id, dest_id = data[ 9, 16 ].unpack( 'Q>Q>' )
          # puts "debug got PAIRED #{ source_id } #{ dest_id } #{ Time.new } p#{ Process.pid }"

          ext = info[ :source_exts ][ source_id ]
          return if ext.nil? || ext[ :dest_id ]

          ext[ :dest_id ] = dest_id
          info[ :dst_src ][ dest_id ] = source_id
        when DEST_STATUS
          dest_id, biggest_dest_pack_id, continue_source_pack_id  = data[ 9, 24 ].unpack( 'Q>Q>Q>' )
          source_id = info[ :dst_src ][ dest_id ]
          return unless source_id

          ext = info[ :source_exts ][ source_id ]
          return unless ext

          # 更新对面发到几
          if biggest_dest_pack_id > ext[ :biggest_dest_pack_id ]
            ext[ :biggest_dest_pack_id ] = biggest_dest_pack_id
          end

          # 更新对面收到几，释放写后
          if continue_source_pack_id > ext[ :completed_pack_id ]
            wmems = ext[ :wmems ]
            pack_ids = wmems.keys.select { | pack_id | pack_id <= continue_source_pack_id }
            pack_ids.each { | pack_id | wmems.delete( pack_id ) }
            info[ :wmems_size ] -= pack_ids.size
            # puts "debug completed #{ continue_source_pack_id } wmems #{ info[ :wmems_size ] }"
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

            # puts "debug #{ ext[ :continue_dest_pack_id ] }/#{ ext[ :biggest_dest_pack_id ] } send MISS #{ ranges.size }"
            ranges.each do | pack_id_begin, pack_id_end |
              ctlmsg = [
                0,
                MISS,
                dest_id,
                pack_id_begin,
                pack_id_end
              ].pack( 'Q>CQ>Q>Q>' )

              send_pack( @tun, ctlmsg,  @tun_info[ :tund_addr ] )
            end
          end
        when MISS
          source_id, pack_id_begin, pack_id_end = data[ 9, 24 ].unpack( 'Q>Q>Q>' )
          ext = info[ :source_exts ][ source_id ]
          return unless ext

          ( pack_id_begin..pack_id_end ).each do | pack_id |
            data, add_at = ext[ :wmems ][ pack_id ]
            break if now - add_at < STATUS_INTERVAL

            if data
              send_pack( tun, data, info[ :tund_addr ] )
              ext[ :last_traffic_at ] = now
            end
          end
        when FIN1
          # > 2-1. recv fin1 -> send got_fin1 -> ext.is_dest_closed = true
          #   2-2. all sent && ext.biggest_dest_pack_id == ext.continue_dest_pack_id -> add closing source
          #   2-3. source.close -> ext.is_dest_closed ? yes -> del ext -> loop send fin2
          #   2-4. recv got_fin2 -> break loop

          # puts "debug 2-1. recv fin1 -> send got_fin1 -> ext.is_dest_closed = true #{ Time.new } p#{ Process.pid }"
          dest_id = data[ 9, 8 ].unpack( 'Q>' ).first
          ctlmsg = [
            0,
            GOT_FIN1,
            dest_id
          ].pack( 'Q>CQ>' )

          send_pack( tun, ctlmsg, info[ :tund_addr ] )

          source_id = info[ :dst_src ][ dest_id ]
          return unless source_id

          ext = info[ :source_exts ][ source_id ]
          return unless ext

          ext[ :is_dest_closed ] = true
        when GOT_FIN1
          #   1-1. source.close -> ext.is_dest_closed ? no -> send fin1 loop
          # > 1-2. recv got_fin1 -> break loop
          #   1-3. recv fin2 -> send got_fin2 -> del ext

          # puts "debug 1-2. recv got_fin1 -> break loop #{ Time.new } p#{ Process.pid }"
          source_id = data[ 9, 8 ].unpack( 'Q>' ).first
          info[ :fin1s ].delete( source_id )
        when FIN2
          #   1-1. source.close -> ext.is_dest_closed ? no -> send fin1 loop
          #   1-2. recv got_fin1 -> break loop
          # > 1-3. recv fin2 -> send got_fin2 -> del ext

          # puts "debug 1-3. recv fin2 -> send got_fin2 -> del ext #{ Time.new } p#{ Process.pid }"
          dest_id = data[ 9, 8 ].unpack( 'Q>' ).first
          ctlmsg = [
            0,
            GOT_FIN2,
            dest_id
          ].pack( 'Q>CQ>' )

          send_pack( tun, ctlmsg, info[ :tund_addr ] )

          source_id = info[ :dst_src ].delete( dest_id )
          return unless source_id

          del_source_ext( source_id )
        when GOT_FIN2
          #   2-1. recv fin1 -> send got_fin1 -> ext.is_dest_closed = true
          #   2-2. all sent && ext.biggest_dest_pack_id == ext.continue_dest_pack_id -> add closing source
          #   2-3. source.close -> ext.is_dest_closed ? yes -> del ext -> loop send fin2
          # > 2-4. recv got_fin2 -> break loop

          # puts "debug 2-4. recv got_fin2 -> break loop #{ Time.new } p#{ Process.pid }"
          source_id = data[ 9, 8 ].unpack( 'Q>' ).first
          info[ :fin2s ].delete( source_id )
        when TUND_FIN
          puts "tund fin #{ Time.new } p#{ Process.pid }"
          add_closing( tun )
        end

        return
      end

      source_id = info[ :dst_src ][ dest_id ]
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
        ext[ :last_traffic_at ] = now
        add_buff( ext[ :source ], data )
      else
        ext[ :pieces ][ pack_id ] = data
      end
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
      data, from = get_buff( source )

      if data.empty?
        ext = @tun_info[ :source_exts ][ source.object_id ]
        #   2-1. recv fin1 -> send got_fin1 -> ext.is_dest_closed = true
        # > 2-2. all sent && ext.biggest_dest_pack_id == ext.continue_dest_pack_id -> add closing source
        #   2-3. source.close -> ext.is_dest_closed ? yes -> del ext -> loop send fin2
        #   2-4. recv got_fin2 -> break loop
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
        return
      rescue Exception => e
        add_closing( source )
        return
      end

      data = data[ written..-1 ]
      info[ from ] = data
    end

    ##
    # write tun
    #
    def write_tun( tun )
      if @closings.include?( tun )
        close_tun
        new_tun
        return
      end

      info = @infos[ tun ]

      # 写后缓存超过上限，中断写
      if info[ :wmems_size ] > WMEMS_LIMIT
        unless info[ :paused ]
          puts "pause #{ Time.new } p#{ Process.pid }"
          info[ :paused ] = true
        end

        @writes.delete( tun )
        return
      end

      data, from = get_buff( tun )

      if data.empty?
        @writes.delete( tun )
        return
      end

      len = data[ 0, 2 ].unpack( 'n' ).first
      pack = data[ 2, ( 16 + len ) ]
      source_id, pack_id = pack[ 0, 16 ].unpack( 'Q>Q>' )
      ext = info[ :source_exts ][ source_id ]

      if ext
        send_pack( tun, pack, info[ :tund_addr ] )
        now = Time.new
        ext[ :biggest_pack_id ] = pack_id
        ext[ :wmems ][ pack_id ] = [ pack, now ]
        ext[ :last_traffic_at ] = now
        info[ :wmems_size ] += 1
      end

      data = data[ ( 18 + len )..-1 ]
      info[ from ] = data
    end

    def new_tun
      tun = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      tun.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )

      tun_id = tun.object_id
      tun_info = {
        wbuff: '',                                            # 写前缓存
        cache: '',                                            # 块读出缓存
        filename: [ Process.pid, tun_id ].join( '-' ),        # 块名
        chunk_dir: @tun_chunk_dir,                            # 块目录
        chunks: [],                                           # 块文件名，wbuff每超过1.4M落一个块
        chunk_seed: 0,                                        # 块序号
        tund_addr: nil,                                       # 远端地址
        dst_src: {},                                          # dest_id => source_id
        sources: [],                                          # 开着的source
        source_exts: {},                                      # 传输相关 source_id => {}
        fin1s: [],                                            # fin1: source已关闭，等待对面收完流量 source_id
        fin2s: [],                                            # fin2: 流量已收完 source_id
        last_coming_at: nil,                                  # 上一次来流量的时间
        wmems_size: 0,                                        # 写后缓存总个数
        paused: false                                         # 是否暂停写
      }

      @tun = tun
      @socks[ tun_id ] = tun
      @roles[ tun ] = :tun
      @tun_info = tun_info
      @infos[ tun ] = tun_info

      add_read( tun )
      loop_send_hello
    end

    def loop_expire
      Thread.new do
        loop do
          sleep CHECK_EXPIRE_INTERVAL

          @mutex.synchronize do
            if @tun_info[ :last_coming_at ] && ( Time.new - @tun_info[ :last_coming_at ] > EXPIRE_AFTER )
              @ctlw.write( [ CTL_CLOSE_SOCK, [ @tun.object_id ].pack( 'Q>' ) ].join )
            end
          end
        end
      end
    end

    def loop_send_heartbeat
      Thread.new do
        loop do
          sleep HEARTBEAT_INTERVAL

          @mutex.synchronize do
            send_heartbeat
          end
        end
      end
    end

    def loop_send_status
      Thread.new do
        loop do
          sleep STATUS_INTERVAL

          if !@tun.closed? && @tun_info[ :tund_addr ] && @tun_info[ :source_exts ].any?
            @mutex.synchronize do
              now = Time.new

              @tun_info[ :source_exts ].each do | source_id, ext |
                if ext[ :last_traffic_at ] && ( now - ext[ :last_traffic_at ] < SEND_STATUS_UNTIL )
                  ctlmsg = [
                    0,
                    SOURCE_STATUS,
                    source_id,
                    ext[ :biggest_pack_id ],
                    ext[ :continue_dest_pack_id ]
                  ].pack( 'Q>CQ>Q>Q>' )

                  send_pack( @tun, ctlmsg, @tun_info[ :tund_addr ] )
                end
              end
            end
          end

          if !@tun.closed? && @tun_info[ :paused ] && ( @tun_info[ :wmems_size ].size < RESUME_BELOW )
            @mutex.synchronize do
              puts "resume #{ Time.new } p#{ Process.pid }"
              @ctlw.write( CTL_RESUME )
              @tun_info[ :paused ] = false
            end
          end
        end
      end
    end

    def loop_send_hello
      Thread.new do
        100.times do
          break if @tun.closed?

          if @tun_info[ :tund_addr ]
            # puts "debug already got tund addr, break hello loop #{ Time.new } p#{ Process.pid }"
            break
          end

          @mutex.synchronize do
            # puts "debug send hello #{ Time.new } p#{ Process.pid }"
            send_pack( @tun, @hex.hello, @roomd_addr )
          end

          sleep 1
        end
      end
    end

    def loop_send_a_new_source( source_id, original_dst )
      Thread.new do
        100.times do
          break if @tun.closed?

          if @tun_info[ :tund_addr ]
            ext = @tun_info[ :source_exts ][ source_id ]

            if ext.nil? || ext[ :dest_id ]
              # puts "debug break a new source loop #{ Time.new } p#{ Process.pid }"
              break
            end

            @mutex.synchronize do
              ctlmsg = [ [ 0, A_NEW_SOURCE, source_id ].pack( 'Q>CQ>' ), original_dst ].join
              # puts "debug send a new source #{ Time.new } p#{ Process.pid }"
              send_pack( @tun, ctlmsg, @tun_info[ :tund_addr ] )
            end
          end

          sleep 1
        end
      end
    end

    def loop_send_fin1( source_id )
      Thread.new do
        100.times do
          if @tun.closed? || !@tun_info[ :fin1s ].include?( source_id )
            # puts "debug break send fin1 loop #{ Time.new } p#{ Process.pid }"
            break
          end

          @mutex.synchronize do
            ctlmsg = [
              0,
              FIN1,
              source_id
            ].pack( 'Q>CQ>' )
            # puts "debug send FIN1 #{ source_id } #{ Time.new } p#{ Process.pid }"
            send_pack( @tun, ctlmsg, @tun_info[ :tund_addr ] )
          end

          sleep 1
        end
      end
    end

    def loop_send_fin2( source_id )
      Thread.new do
        100.times do
          if @tun.closed? || !@tun_info[ :fin2s ].include?( source_id )
            # puts "debug break send fin2 loop #{ Time.new } p#{ Process.pid }"
            break
          end

          @mutex.synchronize do
            ctlmsg = [
              0,
              FIN2,
              source_id
            ].pack( 'Q>CQ>' )
            # puts "debug send FIN2 #{ source_id } #{ Time.new } p#{ Process.pid }"
            send_pack( @tun, ctlmsg, @tun_info[ :tund_addr ] )
          end

          sleep 1
        end
      end
    end

    def send_heartbeat
      return if @tun.closed? || @tun_info[ :tund_addr ].nil?

      ctlmsg = [ 0, HEARTBEAT, rand( 128 ) ].pack( 'Q>CC' )
      send_pack( @tun, ctlmsg, @tun_info[ :tund_addr ] )
    end

    def send_pack( sock, data, target_sockaddr )
      begin
        sock.sendmsg( data, 0, target_sockaddr )
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

    def del_source_ext( source_id )
      ext = @tun_info[ :source_exts ].delete( source_id )
      return if ext.nil? || ext[ :wmems ].empty?

      @tun_info[ :wmems_size ] -= ext[ :wmems ].size
      # puts "debug delete ext, wmems #{ @tun_info[ :wmems_size ] } #{ Time.new } p#{ Process.pid }"
    end

    def close_tun
      close_sock( @tun )
      @tun_info[ :sources ].each { | source | add_closing( source ) }
    end

    def close_source( source )
      close_sock( source )
      return if @tun.closed?

      @tun_info[ :sources ].delete( source )
      source_id = source.object_id
      ext = @tun_info[ :source_exts ][ source_id ]

      if ext
        ext[ :pieces ].clear

        if ext[ :is_dest_closed ]
          #   2-1. recv fin1 -> send got_fin1 -> ext.is_dest_closed = true
          #   2-2. all sent && ext.biggest_dest_pack_id == ext.continue_dest_pack_id -> add closing source
          # > 2-3. source.close -> ext.is_dest_closed ? yes -> del ext -> loop send fin2
          #   2-4. recv got_fin2 -> break loop

          # puts "debug 2-3. source.close -> ext.is_dest_closed ? yes -> del ext -> loop send fin2 #{ Time.new } p#{ Process.pid }"
          @tun_info[ :dst_src ].delete( ext[ :dest_id ] )
          del_source_ext( source_id )

          unless @tun_info[ :fin2s ].include?( source_id )
            @tun_info[ :fin2s ] << source_id
            loop_send_fin2( source_id )
          end
        else
          # > 1-1. source.close -> ext.is_dest_closed ? no -> send fin1 loop
          #   1-2. recv got_fin1 -> break loop
          #   1-3. recv fin2 -> send got_fin2 -> del ext

          # puts "debug 1-1. source.close -> ext.is_dest_closed ? no -> send fin1 loop #{ Time.new } p#{ Process.pid }"
          unless @tun_info[ :fin1s ].include?( source_id )
            @tun_info[ :fin1s ] << source_id
            loop_send_fin1( source_id )
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
