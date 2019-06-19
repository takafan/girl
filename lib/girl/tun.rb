require 'girl/head'
require 'girl/hex'
require 'girl/version'
require 'socket'

##
# Girl::Tun - tcp流量正常的到达目的地。近端。
#
# usage
# =====
#
# 1. Girl::Tund.new( 9090 ).looping # 远端
#
# 2. Girl::Tun.new( '{ your.server.ip }', 9090, 1919 ).looping # 近端
#
# 3. dig +short www.google.com @127.0.0.1 -p1717 # dig with girl/resolv, got 216.58.217.196
#
# 4. iptables -t nat -A OUTPUT -p tcp -d 216.58.217.196 -j REDIRECT --to-ports 1919
#
# 5. curl https://www.google.com/
#
# 包结构
# ======
#
# 流量打包成udp，在tun-tund之间传输，包结构：
#
# N: 1+ source/dest_id -> N: pack_id -> traffic
#    0  ctlmsg         -> C: 1 heartbeat          -> C: random char
#                            2 a new source       -> NnnN: source_id dst_family dst_port dst_ip
#                            3 paired             -> NN: source_id dest_id
#                            4 confirm a pack     -> NN: source/dest_id pack_id
#                            5 dest fin           -> NN: dest_id last_pack_id
#                            6 source fin         -> NN: source_id last_pack_id
#                            7 confirm dest fin   -> N: dest_id
#                            8 confirm source fin -> N: source_id
#                            9 tund fin
#                            10 tun fin
#
module Girl
  class Tun
    ##
    # tund_ip          远端ip
    # roomd_port       roomd端口，roomd用于配对tun-tund
    # redir_port       本地端口，同时配置iptables把流量引向这个端口
    # source_chunk_dir 文件缓存目录，缓存source来不及写的流量
    # tun_chunk_dir    文件缓存目录，缓存tun来不及写的流量
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
      @roles = {} # sock => :redir / :source / :tun
      @infos = {}
      @closings = []
      @reads = []
      @writes = []

      new_redir
      new_tun
    end

    def looping
      puts 'looping'

      loop_heartbeat
      loop_resend
      loop_resume
      loop_clean

      loop do
        rs, ws = IO.select( @reads, @writes )

        @mutex.synchronize do
          rs.each do | sock |
            case @roles[ sock ]
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
      unless @tun.closed?
        ctlmsg = [ 0, TUN_FIN ].pack( 'NC' )
        send_pack( @tun, ctlmsg, @tun_info[ :tund_addr ] )
      end

      exit
    end

    private

    def loop_heartbeat
      Thread.new do
        loop do
          sleep 59

          @mutex.synchronize do
            send_heartbeat
          end
        end
      end
    end

    def loop_resend
      Thread.new do
        loop do
          sleep RESEND_INTERVAL

          if @tun_info[ :queue ].any?
            @mutex.synchronize do
              now = Time.new
              resends = []

              while @tun_info[ :queue ].any?
                mem_sym, mem_id, add_at, times = @tun_info[ :queue ].first

                if now - add_at < RESEND_AFTER
                  break
                end

                @tun_info[ :queue ].shift

                if mem_sym == :traffic
                  source_id, pack_id = mem_id
                  packs = @tun_info[ :wmems ][ mem_sym ][ source_id ]

                  if packs
                    pack = packs[ pack_id ]
                  end
                else
                  source_id = mem_id
                  pack = @tun_info[ :wmems ][ mem_sym ][ source_id ]
                end

                if pack
                  if times > RESEND_LIMIT
                    puts "resend traffic out of #{ RESEND_LIMIT } #{ now }"
                    source = @tun_info[ :sources ][ source_id ]

                    if source && !source.closed?
                      close_source( source )
                    end
                  else
                    resends << [ pack, mem_sym, mem_id, times ]
                  end
                end
              end

              resends.sort{ | a, b | a.last <=> b.last }.reverse.each do | pack, mem_sym, mem_id, times |
                send_pack( @tun, pack, @tun_info[ :tund_addr ], mem_sym, mem_id, times + 1 )
              end
            end
          end
        end
      end
    end

    def loop_resume
      Thread.new do
        loop do
          sleep RESUME_INTERVAL

          if @tun_info[ :paused ] && ( @tun_info[ :queue ].size < RESUME_BELOW )
            @mutex.synchronize do
              space = QUEUE_LIMIT - @tun_info[ :queue ].size

              while space > 0
                data, from = get_buff( @tun )

                if data.empty?
                  @tun_info[ :paused ] = false
                  break
                end

                send_buff( @tun, data, from )
                space -= 1
              end
            end
          end
        end
      end
    end

    def loop_clean
      Thread.new do
        loop do
          sleep 30

          if @tun_info[ :source_fin2s ].any? && @tun_info[ :wbuff ].empty? && @tun_info[ :cache ].empty? && @tun_info[ :chunks ].empty?
            @mutex.synchronize do
              @tun_info[ :source_fin2s ].size.times do
                source_id = @tun_info[ :source_fin2s ].shift

                # 若该source_id的写后为空，删除该节点。反之加回 :source_fin2s。
                if @tun_info[ :wmems ][ :traffic ][ source_id ].empty?
                  delete_wmem_traffic( source_id )
                else
                  @tun_info[ :source_fin2s ] << source_id
                end
              end
            end
          end
        end
      end
    end

    def read_redir( sock )
      begin
        source, addrinfo = sock.accept_nonblock
      rescue IO::WaitReadable, Errno::EINTR => e
        puts "accept source #{ e.class }"
        return
      end

      begin
        # /usr/include/linux/netfilter_ipv4.h
        option = source.getsockopt( Socket::SOL_IP, 80 )
      rescue Exception => e
        puts "get SO_ORIGINAL_DST #{ e.class }"
        source.close
        return
      end

      source_id = source.object_id
      @roles[ source ] = :source
      @infos[ source ] = {
        id: source_id,
        wbuff: '',
        cache: '',
        filename: [ Process.pid, source_id ].join( '-' ),
        chunk_dir: @source_chunk_dir,
        chunks: [],
        chunk_seed: 0,
        pcur: 0,
        dest_pcur: 0,
        pieces: {},
        dest_last_pack_id: nil
      }
      @reads << source
      @tun_info[ :sources ][ source_id ] = source
      @tun_info[ :wmems ][ :traffic ][ source_id ] = {}
      ctlmsg = [ [ 0, A_NEW_SOURCE, source_id ].pack( 'NCN' ), option.data ].join
      send_pack( @tun, ctlmsg, @tun_info[ :tund_addr ], :a_new_source, source_id )
    end

    def read_source( sock )
      begin
        data = sock.read_nonblock( PACK_SIZE )
      rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
        return
      rescue Exception => e
        add_closing( sock )
        return
      end

      info = @infos[ sock ]
      pack_id = info[ :pcur ] + 1

      # ssh的第一段流量是明文版本号，https的第一段流量含明文域名，如果需要，混淆它。
      # 覆盖encode方法自定义混淆。
      if pack_id == 1
        data = @hex.encode( data )
      end

      prefix = [ data.bytesize, info[ :id ], pack_id ].pack( 'nNN' )
      add_buff( @tun, [ prefix, data ].join, !info[ :paused ] )
      info[ :pcur ] = pack_id
    end

    def read_tun( sock )
      info = @infos[ sock ]
      data, addrinfo, rflags, *controls = sock.recvmsg
      dest_id = data[ 0, 4 ].unpack( 'N' ).first

      if dest_id == 0
        ctl_num = data[ 4 ].unpack( 'C' ).first

        case ctl_num
        when PAIRED
          source_id, dest_id = data[ 5, 8 ].unpack( 'NN' )
          info[ :wmems ][ :a_new_source ].delete( source_id )

          if info[ :dst_src ].include?( dest_id )
            puts " #{ dest_id } already paired"
            return
          end

          info[ :dst_src ][ dest_id ] = source_id
          info[ :src_dst ][ source_id ] = dest_id
        when CONFIRM_A_PACK
          source_id, pack_id = data[ 5, 8 ].unpack( 'NN' )
          packs = info[ :wmems ][ :traffic ][ source_id ]

          if packs
            packs.delete( pack_id )
          end
        when DEST_FIN
          dest_id, last_pack_id = data[ 5, 8 ].unpack( 'NN' )
          ctlmsg = [ 0, CONFIRM_DEST_FIN, dest_id ].pack( 'NCN' )
          send_pack( sock, ctlmsg, info[ :tund_addr ] )
          source_id = info[ :dst_src ][ dest_id ]
          source = info[ :sources ][ source_id ]

          if source.nil? || source.closed?
            return
          end

          source_info = @infos[ source ]
          source_info[ :dest_last_pack_id ] = last_pack_id
          add_write( source )
        when CONFIRM_SOURCE_FIN
          source_id = data[ 5, 4 ].unpack( 'N' ).first

          if info[ :wmems ][ :source_fin ].delete( source_id )
            packs = info[ :wmems ][ :traffic ][ source_id ]

            # 若tun写前为空，该source_id的写后也为空，删除该节点。反之记入 :source_fin2s。
            if info[ :wbuff ].empty? && info[ :cache ].empty? && info[ :chunks ].empty? && packs.empty?
              delete_wmem_traffic( source_id )
            else
              info[ :source_fin2s ] << source_id
            end
          end
        when TUND_FIN
          puts 'tund fin'
          close_tun
          sleep 5
          new_tun
        end

        return
      end

      pack_id = data[ 4, 4 ].unpack( 'N' ).first
      ctlmsg = [ 0, CONFIRM_A_PACK, dest_id, pack_id ].pack( 'NCNN' )
      send_pack( sock, ctlmsg, info[ :tund_addr ] )
      source_id = info[ :dst_src ][ dest_id ]
      source = info[ :sources ][ source_id ]

      if source.nil? || source.closed?
        return
      end

      source_info = @infos[ source ]

      if pack_id <= source_info[ :dest_pcur ]
        return
      end

      data = data[ 8..-1 ]

      # 解混淆
      if pack_id == 1
        data = @hex.decode( data )
      end

      # 放进source的写前缓存，跳号放碎片缓存
      if pack_id - source_info[ :dest_pcur ] == 1
        while source_info[ :pieces ].include?( pack_id + 1 )
          data << source_info[ :pieces ].delete( pack_id + 1 )
          pack_id += 1
        end

        add_buff( source, data )
        source_info[ :dest_pcur ] = pack_id
      else
        source_info[ :pieces ][ pack_id ] = data
      end
    end

    def write_source( sock )
      if @closings.include?( sock )
        close_source( sock )
        @closings.delete( sock )
        return
      end

      info = @infos[ sock ]
      data, from = get_buff( sock )

      if data.empty?
        # 流量已收全，关闭source
        if info[ :dest_last_pack_id ] && ( info[ :dest_last_pack_id ] == info[ :dest_pcur ] )
          add_closing( sock )
          return
        end

        @writes.delete( sock )
        return
      end

      begin
        written = sock.write_nonblock( data )
      rescue IO::WaitWritable, Errno::EINTR, IO::WaitReadable => e
        return
      rescue Exception => e
        add_closing( sock )
        return
      end

      data = data[ written..-1 ]
      info[ from ] = data
    end

    def write_tun( sock )
      if @closings.include?( sock )
        close_tun
        @closings.delete( sock )
        return
      end

      info = @infos[ sock ]

      # 重传队列超过上限，中断写
      if info[ :queue ].size > QUEUE_LIMIT
        unless info[ :paused ]
          info[ :paused ] = true
        end

        @writes.delete( sock )
        return
      end

      data, from = get_buff( sock )

      if data.empty?
        @writes.delete( sock )
        return
      end

      send_buff( sock, data, from )
    end

    def send_buff( sock, data, from )
      info = @infos[ sock ]
      len = data[ 0, 2 ].unpack( 'n' ).first
      pack = data[ 2, ( 8 + len ) ]
      source_id, pack_id = pack[ 0, 8 ].unpack( 'NN' )
      send_pack( sock, pack, info[ :tund_addr ], :traffic, [ source_id, pack_id ] )
      data = data[ ( 10 + len )..-1 ]
      info[ from ] = data
    end

    def add_buff( sock, data, add_inst = true )
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

      if add_inst
        add_write( sock )
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

    def send_pack( sock, pack, dest_sockaddr, mem_sym = nil, mem_id = nil, rcount = 0 )
      begin
        sock.sendmsg( pack, 0, dest_sockaddr )
      rescue IO::WaitWritable, Errno::EINTR, IO::WaitReadable => e
        puts "sendmsg #{ e.class }"
      end

      if mem_sym
        if rcount == 0
          if mem_sym == :traffic
            source_id, pack_id = mem_id
            packs = @tun_info[ :wmems ][ mem_sym ][ source_id ]

            if packs
              packs[ pack_id ] = pack
            end
          else
            @tun_info[ :wmems ][ mem_sym ][ mem_id ] = pack
          end
        end

        @tun_info[ :queue ] << [ mem_sym, mem_id, Time.new, rcount ]
      end
    end

    def add_closing( sock )
      unless @closings.include?( sock )
        @closings << sock
      end

      add_write( sock )
    end

    def add_write( sock )
      unless @writes.include?( sock )
        @writes << sock
      end
    end

    def close_sock( sock )
      sock.close
      @roles.delete( sock )
      @reads.delete( sock )
      @writes.delete( sock )
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

    def delete_wmem_traffic( source_id )
      @tun_info[ :wmems ][ :traffic ].delete( source_id )
      dest_id = @tun_info[ :src_dst ].delete( source_id )
      @tun_info[ :dst_src ].delete( dest_id )
    end

    def new_redir
      redir = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      redir.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
      redir.bind( Socket.sockaddr_in( @redir_port, '0.0.0.0' ) )
      redir.listen( 511 )

      @redir = redir
      @roles[ redir ] = :redir
      @reads << redir
    end

    def new_tun
      tun = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      tun.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )
      send_pack( tun, @hex.hello, @roomd_addr )
      rs, ws = IO.select( [ tun ], [], [], 5 )

      unless rs
        raise 'apply for a tunnel timeout'
      end

      data, addrinfo, rflags, *controls = rs.first.recvmsg
      tund_port = data.unpack( 'n' ).first
      puts "tund #{ tund_port }"

      tun_info = {
        wbuff: '', # 写前缓存
        cache: '', # 块读出缓存
        filename: [ Process.pid, tun.object_id ].join( '-' ), # 块名
        chunk_dir: @tun_chunk_dir, # 块目录
        chunks: [], # 块文件名，wbuff每超过1.4M落一个块
        chunk_seed: 0, # 块序号
        wmems: { # 写后缓存
          traffic: {}, # 流量包 source_id => traffics
          a_new_source: {}, # source_id => ctlmsg
          source_fin: {} # source_id => ctlmsg
        },
        source_fin2s: [], # 已被tund确认关闭的source_ids
        tund_addr: Socket.sockaddr_in( tund_port, @tund_ip ), # 远端地址
        sources: {}, # source_id => source
        dst_src: {}, # source_id => dest_id
        src_dst: {}, # dest_id => source_id
        queue: [], # 重传队列
        paused: false # 是否暂停写
      }

      @tun = tun
      @tun_info = tun_info
      @roles[ tun ] = :tun
      @infos[ tun ] = tun_info
      @reads << tun

      send_heartbeat
    end

    def close_source( sock )
      info = close_sock( sock )
      @tun_info[ :sources ].delete( info[ :id ] )

      unless info[ :dest_last_pack_id ]
        ctlmsg = [ 0, SOURCE_FIN, info[ :id ], info[ :pcur ] ].pack( 'NCNN' )
        send_pack( @tun, ctlmsg, @tun_info[ :tund_addr ], :source_fin, info[ :id ] )
      end
    end

    def close_tun
      close_sock( @tun )
      @tun_info[ :sources ].each { | _, source | add_closing( source ) }
    end

    def send_heartbeat
      ctlmsg = [ 0, HEARTBEAT, rand( 128 ) ].pack( 'NCC' )
      send_pack( @tun, ctlmsg, @tun_info[ :tund_addr ] )
    end
  end
end
