module Girl
  class ProxydWorker

    ##
    # initialize
    #
    def initialize( proxyd_port, infod_port )
      @custom = Girl::ProxydCustom.new
      @mutex = Mutex.new
      @reads = []
      @writes = []
      @roles = {}           # sock => :dotr / :proxyd / :infod / :dst / :tund / :tcpd / :streamd
      @tund_infos = {}      # tund => {}
      @tcpd_infos = {}      # tcpd => {}
      @dst_infos = {}       # dst => {}
      @streamd_infos = {}   # streamd => {}
      @tunneling_tunds = {} # tunneling_addr => tund
      @resolv_caches = {}   # domain => [ ip, created_at ]
      @traff_ins = {}       # im => 0
      @traff_outs = {}      # im => 0

      dotr, dotw = IO.pipe
      @dotw = dotw
      add_read( dotr, :dotr )
      new_a_proxyd( proxyd_port )
      new_a_infod( infod_port )
    end

    ##
    # looping
    #
    def looping
      puts "p#{ Process.pid } #{ Time.new } looping"
      loop_check_expire
      loop_check_resume
      loop_check_traff

      loop do
        rs, ws = IO.select( @reads, @writes )

        @mutex.synchronize do
          # 先读，再写，避免打上关闭标记后读到
          rs.each do | sock |
            case @roles[ sock ]
            when :dotr then
              read_dotr( sock )
            when :proxyd then
              read_proxyd( sock )
            when :infod then
              read_infod( sock )
            when :tund then
              read_tund( sock )
            when :tcpd then
              read_tcpd( sock )
            when :dst then
              read_dst( sock )
            when :streamd then
              read_streamd( sock )
            end
          end

          ws.each do | sock |
            case @roles[ sock ]
            when :proxyd then
              write_proxyd( sock )
            when :tund then
              write_tund( sock )
            when :dst then
              write_dst( sock )
            when :streamd then
              write_streamd( sock )
            end
          end
        end
      end
    rescue Interrupt => e
      puts e.class
      quit!
    end

    ##
    # quit!
    #
    def quit!
      data = [ 0, TUND_FIN ].pack( 'Q>C' )

      @tund_infos.each do | tund, tund_info |
        if !tund.closed? && tund_info[ :tun_addr ] then
          # puts "debug1 send tund fin"
          tund.sendmsg( data, 0, tund_info[ :tun_addr ] )
        end
      end

      # puts "debug1 exit"
      exit
    end

    private

    ##
    # add proxyd ctlmsg
    #
    def add_proxyd_ctlmsg_tund_port( tund_info )
      data = [ 0, TUND_PORT, tund_info[ :port ], tund_info[ :tcpd_port ] ].pack( 'Q>Cnn' )
      @proxyd_info[ :ctlmsgs ] << [ data, tund_info[ :tun_addr ] ]
      add_write( @proxyd )
    end

    ##
    # add ctlmsg
    #
    def add_ctlmsg( tund, data )
      tund_info = @tund_infos[ tund ]
      tund_info[ :ctlmsgs ] << data
      add_write( tund )
    end

    ##
    # add read
    #
    def add_read( sock, role = nil )
      unless @reads.include?( sock ) then
        @reads << sock

        if role then
          @roles[ sock ] = role
        end
      end
    end

    ##
    # add write
    #
    def add_write( sock )
      unless @writes.include?( sock ) then
        @writes << sock
      end
    end

    ##
    # close dst
    #
    def close_dst( dst )
      # puts "debug1 close dst"
      close_sock( dst )
      dst_info = del_dst_info( dst )
      streamd = dst_info[ :streamd ]

      if streamd then
        close_read_streamd( streamd )
        set_streamd_closing_write( streamd )
      end
    end

    ##
    # close read dst
    #
    def close_read_dst( dst )
      return if dst.closed?
      # puts "debug1 close read dst"
      dst.close_read
      @reads.delete( dst )

      if dst.closed? then
        # puts "debug1 delete dst info"
        @roles.delete( dst )
        dst_info = del_dst_info( dst )
      else
        dst_info = @dst_infos[ dst ]
      end

      dst_info[ :paused ] = false
      dst_info
    end

    ##
    # close read streamd
    #
    def close_read_streamd( streamd )
      return if streamd.closed?
      # puts "debug1 close read streamd"
      streamd.close_read
      @reads.delete( streamd )

      if streamd.closed? then
        # puts "debug1 delete streamd info"
        @roles.delete( streamd )
        streamd_info = @streamd_infos.delete( streamd )
      else
        streamd_info = @streamd_infos[ streamd ]
      end

      streamd_info
    end

    ##
    # close sock
    #
    def close_sock( sock )
      sock.close
      @reads.delete( sock )
      @writes.delete( sock )
      @roles.delete( sock )
    end

    ##
    # close streamd
    #
    def close_streamd( streamd )
      # puts "debug1 close streamd"
      close_sock( streamd )
      streamd_info = @streamd_infos.delete( streamd )
      dst = streamd_info[ :dst ]

      if dst then
        close_read_dst( dst )
        set_dst_closing_write( dst )
      end
    end

    ##
    # close tund
    #
    def close_tund( tund )
      # puts "debug1 close tund"
      close_sock( tund )
      tund_info = @tund_infos.delete( tund )
      tcpd = tund_info[ :tcpd ]
      close_sock( tcpd )
      @tcpd_infos.delete( tcpd )
      tund_info[ :dsts ].each{ | _, dst | set_dst_closing( dst ) }
      @tunneling_tunds.delete( tund_info[ :tun_addr ] )
    end

    ##
    # close write dst
    #
    def close_write_dst( dst )
      return if dst.closed?
      # puts "debug1 close write dst"
      dst.close_write
      @writes.delete( dst )

      if dst.closed? then
        # puts "debug1 delete dst info"
        @roles.delete( dst )
        dst_info = del_dst_info( dst )
      else
        dst_info = @dst_infos[ dst ]
      end

      dst_info[ :closed_write ] = true
      dst_info
    end

    ##
    # close write streamd
    #
    def close_write_streamd( streamd )
      return if streamd.closed?
      # puts "debug1 close write streamd"
      streamd.close_write
      @writes.delete( streamd )

      if streamd.closed? then
        # puts "debug1 delete streamd info"
        @roles.delete( streamd )
        streamd_info = @streamd_infos.delete( streamd )
      else
        streamd_info = @streamd_infos[ streamd ]
      end

      streamd_info[ :closed_write ] = true
      streamd_info
    end

    ##
    # deal with destination addr
    #
    def deal_with_destination_addr( tund, src_id, destination_addr, domain_port )
      dst = Socket.new( Addrinfo.new( destination_addr ).ipv4? ? Socket::AF_INET : Socket::AF_INET6, Socket::SOCK_STREAM, 0 )
      dst.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )

      begin
        dst.connect_nonblock( destination_addr )
      rescue IO::WaitWritable
      rescue Exception => e
        puts "p#{ Process.pid } #{ Time.new } connect destination #{ domain_port } #{ e.class }"
        return false
      end

      dst_id = dst.local_address.ip_port
      tund_info = @tund_infos[ tund ]

      @dst_infos[ dst ] = {
        id: dst_id,               # id
        tund: tund,               # 对应tund
        im: tund_info[ :im ],     # 标识
        domain_port: domain_port, # 目的地和端口
        rbuff: '',                # 对应的streamd没准备好，暂存读到的流量
        streamd: nil,             # 对应的streamd
        wbuff: '',                # 从streamd读到的流量
        src_id: src_id,           # 近端src id
        created_at: Time.new,     # 创建时间
        last_recv_at: nil,        # 上一次收到新流量（由streamd收到）的时间
        last_sent_at: nil,        # 上一次发出流量（由streamd发出）的时间
        paused: false,            # 是否已暂停读
        closing: false,           # 准备关闭
        closing_write: false,     # 准备关闭写
        closed_write: false       # 已关闭写
      }

      add_read( dst, :dst )

      tund_info[ :dst_ids ][ src_id ] = dst_id
      tund_info[ :dsts ][ dst_id ] = dst

      data = [ 0, PAIRED, src_id, dst_id ].pack( 'Q>CQ>n' )
      # puts "debug1 add ctlmsg paired #{ src_id } #{ dst_id }"
      add_ctlmsg( tund, data )
      true
    end

    ##
    # del dst info
    #
    def del_dst_info( dst )
      dst_info = @dst_infos.delete( dst )
      tund = dst_info[ :tund ]

      unless tund.closed? then
        tund_info = @tund_infos[ tund ]
        tund_info[ :dsts ].delete( dst_info[ :id ] )
        tund_info[ :dst_ids ].delete( dst_info[ :src_id ] )
      end

      dst_info
    end

    ##
    # loop check expire
    #
    def loop_check_expire
      Thread.new do
        loop do
          sleep CHECK_EXPIRE_INTERVAL

          @mutex.synchronize do
            trigger = false
            now = Time.new

            @tund_infos.each do | tund, tund_info |
              last_recv_at = tund_info[ :last_recv_at ] || tund_info[ :created_at ]

              if tund_info[ :dsts ].empty? && ( now - last_recv_at >= EXPIRE_AFTER ) then
                puts "p#{ Process.pid } #{ Time.new } expire tund #{ tund_info[ :port ] }"
                set_tund_closing( tund )
                trigger = true
              end
            end

            @dst_infos.each do | dst, dst_info |
              last_recv_at = dst_info[ :last_recv_at ] || dst_info[ :created_at ]
              last_sent_at = dst_info[ :last_sent_at ] || dst_info[ :created_at ]

              if ( now - last_recv_at >= EXPIRE_AFTER ) && ( now - last_sent_at >= EXPIRE_AFTER ) then
                puts "p#{ Process.pid } #{ Time.new } expire dst #{ dst_info[ :domain_port ] }"
                set_dst_closing( dst )
                trigger = true
              end
            end

            next_tick if trigger
          end
        end
      end
    end

    ##
    # loop check resume
    #
    def loop_check_resume
      Thread.new do
        loop do
          sleep CHECK_RESUME_INTERVAL

          @mutex.synchronize do
            trigger = false

            @dst_infos.select{ | _, dst_info | dst_info[ :paused ] }.each do | dst, dst_info |
              streamd = dst_info[ :streamd ]
              streamd_info = @streamd_infos[ streamd ]

              if streamd_info[ :wbuff ].size < RESUME_BELOW then
                puts "p#{ Process.pid } #{ Time.new } resume dst #{ dst_info[ :domain_port ] }"
                dst_info[ :paused ] = false
                add_read( dst )
                trigger = true
              end
            end

            @streamd_infos.select{ | _, streamd_info | streamd_info[ :paused ] }.each do | streamd, streamd_info |
              dst = streamd_info[ :dst ]
              dst_info = @dst_infos[ dst ]

              if dst_info[ :wbuff ].size < RESUME_BELOW then
                puts "p#{ Process.pid } #{ Time.new } resume streamd #{ streamd_info[ :domain_port ] }"
                streamd_info[ :paused ] = false
                add_read( streamd )
                trigger = true
              end
            end

            next_tick if trigger
          end
        end
      end
    end

    ##
    # loop check traff
    #
    def loop_check_traff
      if RESET_TRAFF_DAY > 0 then
        Thread.new do
          loop do
            sleep CHECK_TRAFF_INTERVAL

            @mutex.synchronize do
              if Time.new.day == RESET_TRAFF_DAY then
                puts "p#{ Process.pid } #{ Time.new } reset traffs"
                @traff_ins.transform_values!{ | _ | 0 }
                @traff_outs.transform_values!{ | _ | 0 }
              end
            end
          end
        end
      end
    end

    ##
    # new a proxyd
    #
    def new_a_proxyd( proxyd_port )
      proxyd = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      proxyd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      proxyd.bind( Socket.sockaddr_in( proxyd_port, '0.0.0.0' ) )

      puts "p#{ Process.pid } #{ Time.new } proxyd bind on #{ proxyd_port }"
      @proxyd = proxyd
      @proxyd_info = {
        ctlmsgs: [] # [ ctlmsg, to_addr ]
      }

      add_read( proxyd, :proxyd )
    end

    ##
    # new a infod
    #
    def new_a_infod( infod_port )
      infod = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      infod.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      infod.bind( Socket.sockaddr_in( infod_port, '127.0.0.1' ) )

      puts "p#{ Process.pid } #{ Time.new } infod bind on #{ infod_port }"
      add_read( infod, :infod )
    end

    ##
    # next tick
    #
    def next_tick
      @dotw.write( '.' )
    end

    ##
    # resolve domain
    #
    def resolve_domain( tund, src_id, domain_port )
      resolv_cache = @resolv_caches[ domain_port ]

      if resolv_cache then
        destination_addr, created_at = resolv_cache

        if Time.new - created_at < RESOLV_CACHE_EXPIRE then
          # puts "debug1 #{ domain_port } hit resolv cache #{ Addrinfo.new( destination_addr ).inspect }"
          deal_with_destination_addr( tund, src_id, destination_addr, domain_port )
          return
        end

        # puts "debug1 expire #{ domain_port } resolv cache"
        @resolv_caches.delete( domain_port )
      end

      Thread.new do
        colon_idx = domain_port.rindex( ':' )

        if colon_idx then
          destination_domain = domain_port[ 0...colon_idx ]
          destination_port = domain_port[ ( colon_idx + 1 )..-1 ].to_i

          begin
            destination_addr = Socket.sockaddr_in( destination_port, destination_domain )
          rescue Exception => e
            puts "p#{ Process.pid } #{ Time.new } sockaddr in #{ domain_port } #{ e.class }"
          end
        end

        @mutex.synchronize do
          if destination_addr then
            # puts "debug1 resolved #{ domain_port } #{ Addrinfo.new( destination_addr ).inspect }"
            @resolv_caches[ domain_port ] = [ destination_addr, Time.new ]

            unless tund.closed? then
              if deal_with_destination_addr( tund, src_id, destination_addr, domain_port ) then
                next_tick
              end
            end
          end
        end
      end
    end

    ##
    # send data
    #
    def send_data( sock, data, to_addr )
      begin
        written = sock.sendmsg_nonblock( data, 0, to_addr )
      rescue IO::WaitWritable, Errno::EINTR
        return :wait
      rescue Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENETDOWN => e
        puts "p#{ Process.pid } #{ Time.new } sendmsg #{ e.class }"
        return :fatal
      end

      written
    end

    ##
    # set dst closing
    #
    def set_dst_closing( dst )
      return if dst.closed?
      dst_info = @dst_infos[ dst ]
      dst_info[ :closing ] = true

      if dst_info[ :closed_write ] then
        add_read( dst )
      else
        @reads.delete( dst )
        add_write( dst )
      end
    end

    ##
    # set dst closing write
    #
    def set_dst_closing_write( dst )
      return if dst.closed?

      dst_info = @dst_infos[ dst ]
      return if dst_info[ :closed_write ]

      dst_info[ :closing_write ] = true
      add_write( dst )
    end

    ##
    # set streamd closing
    #
    def set_streamd_closing( streamd )
      return if streamd.closed?
      streamd_info = @streamd_infos[ streamd ]
      streamd_info[ :closing ] = true

      if streamd_info[ :closed_write ] then
        add_read( streamd )
      else
        @reads.delete( streamd )
        add_write( streamd )
      end
    end

    ##
    # set streamd closing write
    #
    def set_streamd_closing_write( streamd )
      return if streamd.closed?

      streamd_info = @streamd_infos[ streamd ]
      return if streamd_info[ :closed_write ]

      streamd_info[ :closing_write ] = true
      add_write( streamd )
    end

    ##
    # set tund is closing
    #
    def set_tund_closing( tund )
      return if tund.closed?
      tund_info = @tund_infos[ tund ]
      tund_info[ :closing ] = true
      @reads.delete( tund )
      add_write( tund )
    end

    ##
    # read dotr
    #
    def read_dotr( dotr )
      dotr.read( 1 )
    end

    ##
    # read proxyd
    #
    def read_proxyd( proxyd )
      data, addrinfo, rflags, *controls = proxyd.recvmsg
      from_addr = addrinfo.to_sockaddr

      if @tunneling_tunds.include?( from_addr ) then
        tund = @tunneling_tunds[ from_addr ]
        tund_info = @tund_infos[ tund ]
        puts "p#{ Process.pid } #{ Time.new } resend tund port #{ tund_info[ :port ] }, #{ tund_info[ :stream_port ] }"
        add_proxyd_ctlmsg_tund_port( tund_info )
        return
      end

      result = @custom.check( data, addrinfo )

      if result != :success then
        puts "p#{ Process.pid } #{ Time.new } #{ result }"
        return
      end

      im = data

      unless @traff_ins.include?( im ) then
        @traff_ins[ im ] = 0
        @traff_outs[ im ] = 0
      end

      tund = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      tund.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )
      tund_port = tund.local_address.ip_port
      add_read( tund, :tund )

      tcpd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      tcpd.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 ) if RUBY_PLATFORM.include?( 'linux' )
      tcpd.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )
      tcpd_port = tcpd.local_address.ip_port
      tcpd.listen( 127 )
      add_read( tcpd, :tcpd )

      tund_info = {
        im: im,               # 标识
        port: tund_port,      # 端口
        tcpd: tcpd,           # 对应的tcpd
        tcpd_port: tcpd_port, # tcpd端口
        ctlmsgs: [],          # [ ctlmsg, to_addr ]
        tun_addr: from_addr,  # tun地址
        dsts: {},             # dst_id => dst
        dst_ids: {},          # src_id => dst_id
        created_at: Time.new, # 创建时间
        last_recv_at: nil,    # 上一次收到流量的时间
        closing: false,       # 准备关闭
        changed_tun_addr: nil # 记录到和tun addr不符的来源地址
      }

      @tunneling_tunds[ from_addr ] = tund
      @tund_infos[ tund ] = tund_info
      @tcpd_infos[ tcpd ] = {
        tund: tund
      }

      puts "p#{ Process.pid } #{ Time.new } a new tunnel #{ addrinfo.ip_unpack.inspect } - #{ tund_port }, #{ tcpd_port }, #{ @tund_infos.size } tunds"
      add_proxyd_ctlmsg_tund_port( tund_info )
    end

    ##
    # read infod
    #
    def read_infod( infod )
      data, addrinfo, rflags, *controls = infod.recvmsg
      ctl_num = data[ 0 ].unpack( 'C' ).first
      # puts "debug1 infod recv #{ ctl_num } #{ addrinfo.inspect }"

      case ctl_num
      when TRAFF_INFOS then
        data2 = [ TRAFF_INFOS ].pack( 'C' )

        @traff_ins.keys.sort.each do | im |
          traff_in = @traff_ins[ im ]
          traff_out = @traff_outs[ im ]
          data2 << [ [ im.bytesize ].pack( 'C' ), im, [ traff_in, traff_out ].pack( 'Q>Q>' ) ].join
        end

        send_data( infod, data2, addrinfo )
      end
    end

    ##
    # read tund
    #
    def read_tund( tund )
      begin
        data, addrinfo, rflags, *controls = tund.recvmsg_nonblock
      rescue IO::WaitReadable, Errno::EINTR
        print 'r'
        return
      end

      from_addr = addrinfo.to_sockaddr
      tund_info = @tund_infos[ tund ]

      if from_addr != tund_info[ :tun_addr ] then
        # 通常是光猫刷新ip和端口，但万一不是，为了避免脏数据注入，关闭tund
        puts "p#{ Process.pid } #{ Time.new } from #{ addrinfo.inspect } not match tun addr #{ Addrinfo.new( tund_info[ :tun_addr ] ).inspect }"
        tund_info[ :changed_tun_addr ] = from_addr
        set_tund_closing( tund )
        return
      end

      pack_id = data[ 0, 8 ].unpack( 'Q>' ).first
      return if pack_id != 0

      tund_info[ :last_recv_at ] = Time.new
      ctl_num = data[ 8 ].unpack( 'C' ).first

      case ctl_num
      when A_NEW_SOURCE then
        src_id = data[ 9, 8 ].unpack( 'Q>' ).first
        dst_id = tund_info[ :dst_ids ][ src_id ]

        if dst_id then
          dst = tund_info[ :dsts ][ dst_id ]
          return unless dst

          if dst.closed? then
            dst_id = 0
          end

          # puts "debug1 resend paired #{ dst_id }"
          data2 = [ 0, PAIRED, src_id, dst_id ].pack( 'Q>CQ>n' )
          add_ctlmsg( tund, data2 )
          return
        end

        data = data[ 17..-1 ]
        domain_port = @custom.decode( data )
        # puts "debug1 a new source #{ src_id } #{ domain_port }"
        resolve_domain( tund, src_id, domain_port )
      when TUN_FIN then
        puts "p#{ Process.pid } #{ Time.new } recv tun fin"
        set_tund_closing( tund )
      end
    end

    ##
    # read tcpd
    #
    def read_tcpd( tcpd )
      begin
        streamd, addrinfo = tcpd.accept_nonblock
      rescue IO::WaitReadable, Errno::EINTR
        print 'r'
        return
      end

      # puts "debug1 accept a streamd"
      tcpd_info = @tcpd_infos[ tcpd ]
      tund = tcpd_info[ :tund ]
      tund_info = @tund_infos[ tund ]

      @streamd_infos[ streamd ] = {
        tund: tund,           # 对应tund
        im: tund_info[ :im ], # 标识
        dst: nil,             # 对应dst
        domain_port: nil,     # dst的目的地和端口
        wbuff: '',            # 写前，写往近端stream
        paused: false,        # 是否已暂停读
        closing: false,       # 准备关闭
        closing_write: false, # 准备关闭写
        closed_write: false   # 已关闭写
      }

      add_read( streamd, :streamd )
    end

    ##
    # read dst
    #
    def read_dst( dst )
      return if dst.closed?

      begin
        data = dst.read_nonblock( READ_SIZE )
      rescue IO::WaitReadable, Errno::EINTR
        print 'r'
        return
      rescue Exception => e
        # puts "debug1 read dst #{ e.class }"
        dst_info = close_read_dst( dst )
        streamd = dst_info[ :streamd ]
        set_streamd_closing_write( streamd ) if streamd
        return
      end

      dst_info = @dst_infos[ dst ]

      # 处理关闭
      if dst_info[ :closing ] then
        close_dst( dst )
        return
      end

      @traff_ins[ dst_info[ :im ] ] += data.bytesize
      streamd = dst_info[ :streamd ]

      if streamd then
        unless streamd.closed? then
          streamd_info = @streamd_infos[ streamd ]
          data = @custom.encode( data )
          # puts "debug2 add streamd.wbuff encoded #{ data.bytesize }"
          streamd_info[ :wbuff ] << data
          add_write( streamd )

          if streamd_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
            puts "p#{ Process.pid } #{ Time.new } pause dst #{ dst_info[ :domain_port ] }"
            dst_info[ :paused ] = true
            @reads.delete( dst )
          end
        end
      else
        dst_info[ :rbuff ] << data

        if dst_info[ :rbuff ].bytesize >= WBUFF_LIMIT then
          # puts "debug1 dst.rbuff full"
          set_dst_closing( dst )
        end
      end
    end

    ##
    # read streamd
    #
    def read_streamd( streamd )
      return if streamd.closed?

      begin
        data = streamd.read_nonblock( READ_SIZE )
      rescue IO::WaitReadable, Errno::EINTR
        print 'r'
        return
      rescue Exception => e
        # puts "debug1 read streamd #{ e.class }"
        streamd_info = close_read_streamd( streamd )
        dst = streamd_info[ :dst ]
        set_dst_closing_write( dst ) if dst
        return
      end

      streamd_info = @streamd_infos[ streamd ]

      # 处理关闭
      if streamd_info[ :closing ] then
        close_streamd( streamd )
        return
      end

      @traff_ins[ streamd_info[ :im ] ] += data.bytesize
      dst = streamd_info[ :dst ]

      unless dst then
        dst_id = data[ 0, 2 ].unpack( 'n' ).first
        tund = streamd_info[ :tund ]

        if tund.closed? then
          set_streamd_closing( streamd )
          return
        end

        tund_info = @tund_infos[ tund ]
        dst = tund_info[ :dsts ][ dst_id ]

        unless dst then
          set_streamd_closing( streamd )
          return
        end

        # puts "debug1 set streamd.dst #{ dst_id }"
        streamd_info[ :dst ] = dst
        dst_info = @dst_infos[ dst ]
        streamd_info[ :domain_port ] = dst_info[ :domain_port ]

        unless dst_info[ :rbuff ].empty? then
          # puts "debug1 encode and move dst.rbuff to streamd.wbuff"
          streamd_info[ :wbuff ] << @custom.encode( dst_info[ :rbuff ] )
        end

        dst_info[ :streamd ] = streamd
        data = data[ 2..-1 ]

        return if data.empty?
      end

      unless dst.closed? then
        dst_info = @dst_infos[ dst ]
        data = @custom.decode( data )
        # puts "debug2 add dst.wbuff decoded #{ data.bytesize }"
        dst_info[ :wbuff ] << data
        dst_info[ :last_recv_at ] = Time.new
        add_write( dst )

        if dst_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
          puts "p#{ Process.pid } #{ Time.new } pause streamd #{ streamd_info[ :domain_port ] }"
          streamd_info[ :paused ] = true
          @reads.delete( streamd )
        end
      end
    end

    ##
    # write proxyd
    #
    def write_proxyd( proxyd )
      # 发ctlmsg
      while @proxyd_info[ :ctlmsgs ].any? do
        data, to_addr = @proxyd_info[ :ctlmsgs ].first
        sent = send_data( proxyd, data, to_addr )

        if sent == :wait then
          puts "p#{ Process.pid } #{ Time.new } wait proxyd send ctlmsg, left #{ @proxyd_info[ :ctlmsgs ].size }"
          return
        else
          @proxyd_info[ :ctlmsgs ].shift
        end
      end

      @writes.delete( proxyd )
    end

    ##
    # write tund
    #
    def write_tund( tund )
      tund_info = @tund_infos[ tund ]

      # 处理关闭
      if tund_info[ :closing ] then
        if tund_info[ :changed_tun_addr ] then
          data = [ 0, IP_CHANGED ].pack( 'Q>C' )
          send_data( tund, data, tund_info[ :changed_tun_addr ] )
        end

        close_tund( tund )
        return
      end

      now = Time.new

      # 发ctlmsg
      while tund_info[ :ctlmsgs ].any? do
        data = tund_info[ :ctlmsgs ].first
        sent = send_data( tund, data, tund_info[ :tun_addr ] )

        if sent == :fatal then
          close_tund( tund )
          return
        elsif sent == :wait then
          puts "p#{ Process.pid } #{ Time.new } wait tund #{ tund_info[ :port ] } send ctlmsg, left #{ tund_info[ :ctlmsgs ].size }"
          return
        end

        tund_info[ :ctlmsgs ].shift
      end

      @writes.delete( tund )
    end

    ##
    # write dst
    #
    def write_dst( dst )
      return if dst.closed?
      dst_info = @dst_infos[ dst ]
      streamd = dst_info[ :streamd ]

      # 处理关闭
      if dst_info[ :closing ] then
        close_dst( dst )
        return
      end

      data = dst_info[ :wbuff ]

      # 写前为空，处理关闭写
      if data.empty? then
        if dst_info[ :closing_write ] then
          close_write_dst( dst )
        else
          @writes.delete( dst )
        end

        return
      end

      # 写入
      begin
        written = dst.write_nonblock( data )
      rescue IO::WaitWritable, Errno::EINTR
        print 'w'
        return
      rescue Exception => e
        # puts "debug1 write dst #{ e.class }"
        close_write_dst( dst )
        close_read_streamd( streamd ) if streamd
        return
      end

      # puts "debug2 written dst #{ written }"
      data = data[ written..-1 ]
      dst_info[ :wbuff ] = data
      @traff_outs[ dst_info[ :im ] ] += written
    end

    ##
    # write streamd
    #
    def write_streamd( streamd )
      return if streamd.closed?
      streamd_info = @streamd_infos[ streamd ]
      dst = streamd_info[ :dst ]

      # 处理关闭
      if streamd_info[ :closing ] then
        close_streamd( streamd )
        return
      end

      data = streamd_info[ :wbuff ]

      # 写前为空，处理关闭写
      if data.empty? then
        if streamd_info[ :closing_write ] then
          close_write_streamd( streamd )
        else
          @writes.delete( streamd )
        end

        return
      end

      # 写入
      begin
        written = streamd.write_nonblock( data )
      rescue IO::WaitWritable, Errno::EINTR
        print 'w'
        return
      rescue Exception => e
        # puts "debug1 write streamd #{ e.class }"
        close_write_streamd( streamd )
        close_read_dst( dst ) if dst
        return
      end

      # puts "debug2 written streamd #{ written }"
      data = data[ written..-1 ]
      streamd_info[ :wbuff ] = data
      @traff_outs[ streamd_info[ :im ] ] += written

      if dst && !dst.closed? then
        dst_info = @dst_infos[ dst ]
        dst_info[ :last_sent_at ] = Time.new
      end
    end

  end
end
