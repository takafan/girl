require 'girl/head'
require 'girl/hex'
require 'girl/version'
require 'socket'

##
# Girl::Tund - tcp流量正常的到达目的地。远端。
#
module Girl
  class Tund
    ##
    # roomd_port     roomd端口，roomd用于配对tun-tund
    # dest_chunk_dir 文件缓存目录，缓存dest来不及写的流量
    # tund_chunk_dir 文件缓存目录，缓存tund来不及写的流量
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
      @infos = {}

      ctlr, ctlw = IO.pipe
      @ctlw = ctlw
      @roles[ ctlr ] = :ctlr
      @reads << ctlr

      new_roomd
    end

    def looping
      puts 'looping'

      loop_resend
      loop_resume
      loop_clean
      loop_expire

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
      ctlmsg = [ 0, TUND_FIN ].pack( 'NC' )

      @roomd_info[ :tunds ].keys.each do | tund |
        if tund.closed?
          next
        end

        tund_info = @infos[ tund ]

        unless tund_info[ :tun_addr ]
          next
        end

        send_pack( tund, ctlmsg, tund_info[ :tun_addr ] )
      end

      exit
    end

    private

    def loop_resend
      Thread.new do
        loop do
          sleep RESEND_INTERVAL

          if @roomd_info[ :queue ].any?
            @mutex.synchronize do
              now = Time.new
              resends = []

              while @roomd_info[ :queue ].any?
                tund, mem_sym, mem_id, add_at, times = @roomd_info[ :queue ].first

                if now - add_at < RESEND_AFTER
                  break
                end

                @roomd_info[ :queue ].shift

                unless tund.closed?
                  tund_info = @infos[ tund ]

                  if mem_sym == :traffic
                    dest_id, pack_id = mem_id
                    packs = tund_info[ :wmems ][ mem_sym ][ dest_id ]

                    if packs
                      pack = packs[ pack_id ]
                    end
                  else
                    dest_id = mem_id
                    pack = tund_info[ :wmems ][ mem_sym ][ dest_id ]
                  end

                  if pack
                    if times >= RESEND_LIMIT
                      puts "resend traffic out of #{ RESEND_LIMIT } #{ Time.new }"
                      dest = tund_info[ :dests ][ dest_id ]

                      if dest && !dest.closed?
                        @ctlw.write( [ CTL_CLOSE_SOCK, [ dest.object_id ].pack( 'N' ) ].join )
                      end
                    else
                      resends << [ tund, pack, tund_info[ :tun_addr ], mem_sym, mem_id, times ]
                    end
                  end
                end
              end

              resends.sort{ | a, b | a.last <=> b.last }.reverse.each do | tund, pack, tun_addr, mem_sym, mem_id, times |
                send_pack( tund, pack, tun_addr, mem_sym, mem_id, times + 1 )
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

          if @roomd_info[ :paused_tunds ].any? && ( @roomd_info[ :queue ].size < RESUME_BELOW )
            @mutex.synchronize do
              space = QUEUE_LIMIT - @roomd_info[ :queue ].size

              @roomd_info[ :paused_tunds ].size.times do
                tund = @roomd_info[ :paused_tunds ].shift

                while space > 0
                  data, from = get_buff( tund )

                  if data.empty?
                    break
                  end

                  send_buff( tund, data, from )
                  space -= 1
                end

                if space <= 0
                  @roomd_info[ :paused_tunds ] << tund
                  break
                end
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

          if @roomd_info[ :dest_fin2s ].any?
            @mutex.synchronize do
              @roomd_info[ :dest_fin2s ].size.times do
                tund, dest_id = @roomd_info[ :dest_fin2s ].shift

                unless tund.closed?
                  tund_info = @infos[ tund ]
                  packs = tund_info[ :wmems ][ :traffic ][ dest_id ]

                  if packs
                    # 若tund写前为空，该dest_id的写后也为空，删除该节点。反之加回 :dest_fin2s。
                    if tund_info[ :wbuff ].empty? && tund_info[ :cache ].empty? && tund_info[ :chunks ].empty? && packs.empty?
                      delete_wmem_traffic( tund_info, dest_id )
                    else
                      @roomd_info[ :dest_fin2s ] << [ tund, dest_id ]
                    end
                  end
                end
              end
            end
          end
        end
      end
    end

    def loop_expire
      Thread.new do
        loop do
          sleep 900

          if @roomd_info[ :tunds ].any?
            @mutex.synchronize do
              now = Time.new

              @roomd_info[ :tunds ].keys.each do | tund |
                info = @infos[ tund ]

                if info[ :last_coming_at ] && ( now - info[ :last_coming_at ] > 1800 )
                  @ctlw.write( [ CTL_CLOSE_SOCK, [ tund.object_id ].pack( 'N' ) ].join )
                end
              end
            end
          end
        end
      end
    end

    def read_ctlr( ctlr )
      case ctlr.read( 1 )
      when CTL_CLOSE_SOCK
        sock_id = ctlr.read( 4 ).unpack( 'N' ).first
        sock = @socks[ sock_id ]

        if sock
          add_closing( sock )
        end
      end
    end

    def read_roomd( sock )
      info = @infos[ sock ]
      data, addrinfo, rflags, *controls = sock.recvmsg
      result = @hex.check( data, addrinfo )

      if result != :success
        puts result
        return
      end

      client = addrinfo.to_sockaddr

      if info[ :clients ].include?( client )
        puts "tunnel already exist #{ addrinfo.ip_unpack.inspect }"
        return
      end

      tund = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      tund.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )
      tund_id = tund.object_id

      @socks[ tund_id ] = tund
      @roles[ tund ] = :tund
      @infos[ tund ] = {
        wbuff: '', # 写前缓存
        cache: '', # 块读出缓存
        filename: [ Process.pid, tund_id ].join( '-' ), # 块名
        chunk_dir: @tund_chunk_dir, # 块目录
        chunks: [], # 块文件名，wbuff每超过1.4M落一个块
        chunk_seed: 0, # 块序号
        wmems: { # 写后缓存
          traffic: {}, # 流量包 dest_id => traffics
          dest_fin: {} # dest_id => ctlmsg
        },
        tun_addr: nil, # 近端地址
        dests: {}, # dest_id => dest
        src_dst: {}, # source_id => dest_id
        dst_src: {}, # dest_id => source_id
        last_coming_at: nil # 上一次来流量的时间
      }
      @reads << tund

      tund_port = tund.local_address.ip_unpack.last
      send_pack( sock, [ tund_port ].pack( 'n' ), client )
      info[ :clients ] << client
      info[ :tunds ][ tund ] = client
      puts "p#{ Process.pid } #{ info[ :tunds ].size } tunds #{ Time.new }"
    end

    def read_dest( sock )
      begin
        data = sock.read_nonblock( PACK_SIZE )
      rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
        return
      rescue Exception => e
        add_closing( sock )
        return
      end

      info = @infos[ sock ]
      tund = info[ :tund ]

      if tund.closed?
        add_closing( sock )
        return
      end

      pack_id = info[ :pcur ] + 1

      if pack_id == 1
        data = @hex.encode( data )
      end

      prefix = [ data.bytesize, info[ :id ], pack_id ].pack( 'nNN' )
      add_inst = !@roomd_info[ :paused_tunds ].include?( tund )
      add_buff( tund, [ prefix, data ].join, add_inst )
      info[ :pcur ] = pack_id
    end

    def read_tund( sock )
      info = @infos[ sock ]
      data, addrinfo, rflags, *controls = sock.recvmsg
      tun_addr = addrinfo.to_sockaddr

      if info[ :tun_addr ].nil?
        info[ :tun_addr ] = tun_addr
        add_write( sock )
      elsif info[ :tun_addr ] != tun_addr
        puts "tun addr not match? #{ addrinfo.ip_unpack.inspect }"
        return
      end

      info[ :last_coming_at ] = Time.new
      source_id = data[ 0, 4 ].unpack( 'N' ).first

      if source_id == 0
        ctl_num = data[ 4 ].unpack( 'C' ).first

        case ctl_num
        when A_NEW_SOURCE
          source_id = data[ 5, 4 ].unpack( 'N' ).first
          dest_id = info[ :src_dst ][ source_id ]

          unless dest_id
            dst_family, dst_port, dst_host = data[ 9, 8 ].unpack( 'nnN' )
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
              id: dest_id,
              wbuff: '',
              cache: '',
              filename: [ Process.pid, dest_id ].join( '-' ),
              chunk_dir: @dest_chunk_dir,
              chunks: [],
              chunk_seed: 0,
              pieces: {}, # 跳号缓存
              pcur: 0, # 打包光标
              source_pcur: 0, # 写前光标
              source_last_pack_id: nil,
              tund: sock
            }
            @reads << dest

            info[ :dests ][ dest_id ] = dest
            info[ :src_dst ][ source_id ] = dest_id
            info[ :dst_src ][ dest_id ] = source_id
            info[ :wmems ][ :traffic ][ dest_id ] = {}
          end

          ctlmsg = [ 0, PAIRED, source_id, dest_id ].pack( 'NCNN' )
          send_pack( sock, ctlmsg, info[ :tun_addr ] )
        when CONFIRM_A_PACK
          dest_id, pack_id = data[ 5, 8 ].unpack( 'NN' )
          packs = info[ :wmems ][ :traffic ][ dest_id ]

          if packs
            packs.delete( pack_id )
          end
        when SOURCE_FIN
          source_id, last_pack_id = data[ 5, 8 ].unpack( 'NN' )
          ctlmsg = [ 0, CONFIRM_SOURCE_FIN, source_id ].pack( 'NCN' )
          send_pack( sock, ctlmsg, info[ :tun_addr ] )
          dest_id = info[ :src_dst ][ source_id ]
          dest = info[ :dests ][ dest_id ]

          if dest.nil? || dest.closed?
            return
          end

          dest_info = @infos[ dest ]
          dest_info[ :source_last_pack_id ] = last_pack_id
          add_write( dest )
        when CONFIRM_DEST_FIN
          dest_id = data[ 5, 4 ].unpack( 'N' ).first

          if info[ :wmems ][ :dest_fin ].delete( dest_id )
            packs = info[ :wmems ][ :traffic ][ dest_id ]

            if packs
              # 若tund写前为空，该dest_id的写后也为空，删除该节点。反之记入 :dest_fin2s。
              if info[ :wbuff ].empty? && info[ :cache ].empty? && info[ :chunks ].empty? && packs.empty?
                delete_wmem_traffic( info, dest_id )
              else
                @roomd_info[ :dest_fin2s ] << [ sock, dest_id ]
              end
            end
          end
        when TUN_FIN
          add_closing( sock )
        end

        return
      end

      pack_id = data[ 4, 4 ].unpack( 'N' ).first
      ctlmsg = [ 0, CONFIRM_A_PACK, source_id, pack_id ].pack( 'NCNN' )
      send_pack( sock, ctlmsg, info[ :tun_addr ] )

      dest_id = info[ :src_dst ][ source_id ]
      dest = info[ :dests ][ dest_id ]

      if dest.nil? || dest.closed?
        return
      end

      dest_info = @infos[ dest ]

      if pack_id <= dest_info[ :source_pcur ]
        return
      end

      data = data[ 8..-1 ]

      # 解混淆
      if pack_id == 1
        data = @hex.decode( data )
      end

      # 放进dest的写前缓存，跳号放碎片缓存
      if pack_id - dest_info[ :source_pcur ] == 1
        while dest_info[ :pieces ].include?( pack_id + 1 )
          data << dest_info[ :pieces ].delete( pack_id + 1 )
          pack_id += 1
        end

        add_buff( dest, data )
        dest_info[ :source_pcur ] = pack_id
      else
        dest_info[ :pieces ][ pack_id ] = data
      end
    end

    def write_dest( sock )
      if @closings.include?( sock )
        close_dest( sock )
        return
      end

      info = @infos[ sock ]
      data, from = get_buff( sock )

      if data.empty?
        # 流量已收全，关闭dest
        if info[ :source_last_pack_id ] && ( info[ :source_last_pack_id ] == info[ :source_pcur ] )
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

    def write_tund( sock )
      if @closings.include?( sock )
        close_tund( sock )
        return
      end

      if @roomd_info[ :queue ].size > QUEUE_LIMIT
        unless @roomd_info[ :paused_tunds ].include?( sock )
          @roomd_info[ :paused_tunds ] << sock
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
      dest_id, pack_id = pack[ 0, 8 ].unpack( 'NN' )
      send_pack( sock, pack, info[ :tun_addr ], :traffic, [ dest_id, pack_id ] )
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
        info = @infos[ sock ]

        if rcount == 0
          if mem_sym == :traffic
            dest_id, pack_id = mem_id
            packs = info[ :wmems ][ mem_sym ][ dest_id ]

            if packs
              packs[ pack_id ] = pack
            end
          else
            info[ :wmems ][ mem_sym ][ mem_id ] = pack
          end
        end

        @roomd_info[ :queue ] << [ sock, mem_sym, mem_id, Time.new, rcount ]
      end
    end

    def add_closing( sock )
      unless @closings.include?( sock )
        @reads.delete( sock )
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

    def delete_wmem_traffic( tund_info, dest_id )
      tund_info[ :wmems ][ :traffic ].delete( dest_id )
      source_id = tund_info[ :dst_src ].delete( dest_id )
      tund_info[ :src_dst ].delete( source_id )
    end

    def new_roomd
      roomd = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      roomd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      roomd.bind( Socket.sockaddr_in( @roomd_port, '0.0.0.0' ) )
      roomd_info = {
        clients: [],
        tunds: {}, # tund => client
        queue: [], # 重传队列
        paused_tunds: [], # 暂停写的tunds
        dest_fin2s: [] # 已被tun确认关闭的dest_ids [ [ tund, dest_id ], .. ]
      }

      @roomd = roomd
      @roomd_info = roomd_info
      @roles[ roomd ] = :roomd
      @infos[ roomd ] = roomd_info
      @reads << roomd
    end

    def close_dest( sock )
      info = close_sock( sock )
      tund = info[ :tund ]

      unless tund.closed?
        tund_info = @infos[ tund ]
        tund_info[ :dests ].delete( info[ :id ] )

        unless info[ :source_last_pack_id ]
          ctlmsg = [ 0, DEST_FIN, info[ :id ], info[ :pcur ] ].pack( 'NCNN' )
          send_pack( tund, ctlmsg, tund_info[ :tun_addr ], :dest_fin, info[ :id ] )
        end
      end
    end

    def close_tund( sock )
      info = close_sock( sock )
      info[ :dests ].each{ | _, dest | close_sock( dest ) }
      @roomd_info[ :paused_tunds ].delete( sock )
      client = @roomd_info[ :tunds ].delete( sock )
      @roomd_info[ :clients ].delete( client )
    end
  end
end
