module Girl
  class SslWorker

    ##
    # initialize
    #
    def initialize( redir_port, cert_path, key_path )
      @reads = []
      @writes = []
      @closing_srcs = []
      @paused_srcs = []
      @paused_dsts = []
      @resume_srcs = []
      @resume_dsts = []
      @roles = ConcurrentHash.new            # sock => :dotr / :redir / :src / :dst
      @src_infos = ConcurrentHash.new        # src => {}
      @dst_infos = ConcurrentHash.new        # dst => {}
      @resolv_caches = ConcurrentHash.new    # domain => [ ip, created_at ]

      dotr, dotw = IO.pipe
      @dotw = dotw
      add_read( dotr, :dotr )
      new_a_redir( redir_port, cert_path, key_path )
    end

    ##
    # looping
    #
    def looping
      puts "p#{ Process.pid } #{ Time.new } looping"
      loop_check_expire
      loop_check_resume

      loop do
        rs, ws = IO.select( @reads, @writes )

        rs.each do | sock |
          case @roles[ sock ]
          when :dotr then
            read_dotr( sock )
          when :redir then
            read_redir( sock )
          when :src then
            read_src( sock )
          when :dst then
            read_dst( sock )
          end
        end

        ws.each do | sock |
          case @roles[ sock ]
          when :src then
            write_src( sock )
          when :dst then
            write_dst( sock )
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
      # puts "debug1 exit"
      exit
    end

    private

    ##
    # add closing src
    #
    def add_closing_src( src )
      return if src.closed? || @closing_srcs.include?( src )
      @closing_srcs << src
      next_tick
    end

    ##
    # add dst wbuff
    #
    def add_dst_wbuff( dst, data )
      dst_info = @dst_infos[ dst ]
      dst_info[ :wbuff ] << data
      add_write( dst )

      if dst_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        puts "p#{ Process.pid } #{ Time.new } pause direct src #{ dst_info[ :domain ] }"
        add_paused_src( dst_info[ :src ] )
      end
    end

    ##
    # add paused dst
    #
    def add_paused_dst( dst )
      return if dst.closed? || @paused_dsts.include?( dst )
      @reads.delete( dst )
      @paused_dsts << dst
    end

    ##
    # add paused src
    #
    def add_paused_src( src )
      return if src.closed? || @paused_srcs.include?( src )
      @reads.delete( src )
      @paused_srcs << src
    end

    ##
    # add read
    #
    def add_read( sock, role = nil )
      return if sock.closed? || @reads.include?( sock )
      @reads << sock

      if role then
        @roles[ sock ] = role
      end

      next_tick
    end

    ##
    # add resume dst
    #
    def add_resume_dst( dst )
      return if @resume_dsts.include?( dst )
      @resume_dsts << dst
      next_tick
    end

    ##
    # add resume src
    #
    def add_resume_src( src )
      return if @resume_srcs.include?( src )
      @resume_srcs << src
      next_tick
    end

    ##
    # add socks5 conn reply
    #
    def add_socks5_conn_reply( src )
      # +----+-----+-------+------+----------+----------+
      # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
      # +----+-----+-------+------+----------+----------+
      # | 1  |  1  | X'00' |  1   | Variable |    2     |
      # +----+-----+-------+------+----------+----------+
      redir_ip, redir_port = @redir_local_address.ip_unpack
      data = [ [ 5, 0, 0, 1 ].pack( 'C4' ), IPAddr.new( redir_ip ).hton, [ redir_port ].pack( 'n' ) ].join
      # puts "debug1 add src.wbuff socks5 conn reply #{ data.inspect }"
      add_src_wbuff( src, data )
    end

    ##
    # add src rbuff
    #
    def add_src_rbuff( src, data )
      src_info = @src_infos[ src ]
      src_info[ :rbuff ] << data

      if src_info[ :rbuff ].bytesize >= WBUFF_LIMIT then
        # puts "debug1 src.rbuff full"
        add_closing_src( src )
      end
    end

    ##
    # add src wbuff
    #
    def add_src_wbuff( src, data )
      return if src.closed? || @closing_srcs.include?( src )
      src_info = @src_infos[ src ]
      src_info[ :wbuff ] << data
      src_info[ :last_recv_at ] = Time.new
      add_write( src )

      if src_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        dst = src_info[ :dst ]

        if dst then
          puts "p#{ Process.pid } #{ Time.new } pause dst #{ src_info[ :destination_domain ] }"
          add_paused_dst( dst )
        end
      end
    end

    ##
    # add write
    #
    def add_write( sock )
      return if sock.closed? || @writes.include?( sock )
      @writes << sock
      next_tick
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
        @writes.delete( dst )
        @roles.delete( dst )
        dst_info = @dst_infos.delete( dst )
      else
        dst_info = @dst_infos[ dst ]
      end

      dst_info
    end

    ##
    # close read src
    #
    def close_read_src( src )
      return if src.closed?
      # puts "debug1 close read src"
      src_info = @src_infos[ src ]
      src_info[ :close_read ] = true

      if src_info[ :close_write ] then
        # puts "debug1 delete src info"
        close_sock( src )
        src_info = @src_infos.delete( src )
      else
        @reads.delete( src )
      end

      src_info
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
    # close src
    #
    def close_src( src )
      return if src.closed?
      # puts "debug1 close src"
      close_sock( src )
      src_info = @src_infos.delete( src )
      dst = src_info[ :dst ]

      if dst then
        close_sock( dst )
        @dst_infos.delete( dst )
      end
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
        @reads.delete( dst )
        @roles.delete( dst )
        dst_info = @dst_infos.delete( dst )
      else
        dst_info = @dst_infos[ dst ]
      end

      dst_info
    end

    ##
    # close write src
    #
    def close_write_src( src )
      return if src.closed?
      # puts "debug1 close write src"
      src_info = @src_infos[ src ]
      src_info[ :close_write ] = true
      
      if src_info[ :close_read ] then
        # puts "debug1 delete src info"
        close_sock( src )
        src_info = @src_infos.delete( src )
      else
        @writes.delete( src )
      end

      src_info
    end

    ##
    # loop check expire
    #
    def loop_check_expire
      Thread.new do
        loop do
          sleep CHECK_EXPIRE_INTERVAL
          now = Time.new

          @src_infos.each do | src, src_info |
            last_recv_at = src_info[ :last_recv_at ] || src_info[ :created_at ]
            last_sent_at = src_info[ :last_sent_at ] || src_info[ :created_at ]
            expire_after = src_info[ :dst ] ? EXPIRE_AFTER : EXPIRE_NEW

            if ( now - last_recv_at >= expire_after ) && ( now - last_sent_at >= expire_after ) then
              puts "p#{ Process.pid } #{ Time.new } expire src #{ expire_after } #{ src_info[ :destination_domain ] }"
              add_closing_src( src )

              unless src_info[ :rbuff ].empty? then
                puts "p#{ Process.pid } #{ Time.new } lost rbuff #{ src_info[ :rbuff ].inspect }"
              end
            end
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

          @paused_srcs.each do | src |
            if src.closed? then
              add_resume_src( src )
            else
              src_info = @src_infos[ src ]
              dst = src_info[ :dst ]

              if dst then
                dst_info = @dst_infos[ dst ]

                if dst_info[ :wbuff ].size < RESUME_BELOW then
                  puts "p#{ Process.pid } #{ Time.new } resume direct src #{ src_info[ :destination_domain ] }"
                  add_resume_src( src )
                end
              end
            end
          end

          @paused_dsts.each do | dst |
            if dst.closed? then
              add_resume_dst( dst )
            else
              dst_info = @dst_infos[ dst ]
              src = dst_info[ :src ]
              src_info = @src_infos[ src ]

              if src_info[ :wbuff ].size < RESUME_BELOW then
                puts "p#{ Process.pid } #{ Time.new } resume dst #{ dst_info[ :domain ] }"
                add_resume_dst( dst )
              end
            end
          end
        end
      end
    end

    ##
    # new a dst
    #
    def new_a_dst( src, ip_info )
      return if src.closed?
      src_info = @src_infos[ src ]
      domain = src_info[ :destination_domain ]
      destination_addr = Socket.sockaddr_in( src_info[ :destination_port ], ip_info.ip_address )
      dst = Socket.new( ip_info.ipv4? ? Socket::AF_INET : Socket::AF_INET6, Socket::SOCK_STREAM, 0 )
      dst.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )

      begin
        dst.connect_nonblock( destination_addr )
      rescue IO::WaitWritable
        # connect nonblock 必抛 wait writable
      rescue Exception => e
        puts "p#{ Process.pid } #{ Time.new } dst connect destination #{ domain } #{ src_info[ :destination_port ] } #{ ip_info.ip_address } #{ e.class }, close src"
        dst.close
        add_closing_src( src )
        return
      end

      # puts "debug1 a new dst #{ dst.local_address.inspect }"
      dst_info = {
        src: src,            # 对应src
        domain: domain,      # 目的地
        wbuff: '',           # 写前
        closing_write: false # 准备关闭写
      }

      @dst_infos[ dst ] = dst_info
      add_read( dst, :dst )
      src_info[ :proxy_type ] = :direct
      src_info[ :dst ] = dst
      add_socks5_conn_reply( src )
    end

    ##
    # new a redir
    #
    def new_a_redir( redir_port, cert_path, key_path )
      redir = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      redir.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
      redir.bind( Socket.sockaddr_in( redir_port, '0.0.0.0' ) )
      redir.listen( 127 )

      @redir_local_address = redir.local_address

      cert = OpenSSL::X509::Certificate.new File.read( cert_path )
      key = OpenSSL::PKey::RSA.new File.read( key_path )
      context = OpenSSL::SSL::SSLContext.new
      context.add_certificate( cert, key )
      redir = OpenSSL::SSL::SSLServer.new redir, context

      puts "p#{ Process.pid } #{ Time.new } redir listen on #{ redir_port }"
      add_read( redir, :redir )
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
    def resolve_domain( src, domain )
      resolv_cache = @resolv_caches[ domain ]

      if resolv_cache then
        ip_info, created_at = resolv_cache

        if Time.new - created_at < RESOLV_CACHE_EXPIRE then
          # puts "debug1 #{ domain } hit resolv cache #{ ip_info.inspect }"
          new_a_dst( src, ip_info )
          return
        end

        # puts "debug1 expire #{ domain } resolv cache"
        @resolv_caches.delete( domain )
      end

      src_info = @src_infos[ src ]
      src_info[ :proxy_type ] = :checking

      Thread.new do
        begin
          ip_info = Addrinfo.ip( domain )
        rescue Exception => e
          puts "p#{ Process.pid } #{ Time.new } resolv #{ domain.inspect } #{ e.class }"
        end

        if ip_info then
          @resolv_caches[ domain ] = [ ip_info, Time.new ]
          puts "p#{ Process.pid } #{ Time.new } resolved #{ domain } #{ ip_info.ip_address }"
          new_a_dst( src, ip_info )
        else
          add_closing_src( src )
        end
      end
    end

    ##
    # set dst closing write
    #
    def set_dst_closing_write( dst )
      return if dst.closed?
      dst_info = @dst_infos[ dst ]
      return if dst_info[ :closing_write ]
      dst_info[ :closing_write ] = true
      add_write( dst )
    end

    ##
    # set src closing write
    #
    def set_src_closing_write( src )
      return if src.closed? || @closing_srcs.include?( src )
      src_info = @src_infos[ src ]
      return if src_info[ :closing_write ]
      src_info[ :closing_write ] = true
      add_write( src )
    end

    ##
    # read dotr
    #
    def read_dotr( dotr )
      dotr.read_nonblock( READ_SIZE )

      if @closing_srcs.any? then
        @closing_srcs.each { | src | close_src( src ) }
        @closing_srcs.clear
      end

      if @resume_srcs.any? then
        @resume_srcs.each do | src |
          add_read( src )
          @paused_srcs.delete( src )
        end

        @resume_srcs.clear
      end

      if @resume_dsts.any? then
        @resume_dsts.each do | dst |
          add_read( dst )
          @paused_dsts.delete( dst )
        end

        @resume_dsts.clear
      end
    end

    ##
    # read redir
    #
    def read_redir( redir )
      begin
        src = redir.accept
      rescue Exception => e
        puts "p#{ Process.pid } #{ Time.new } redir accept #{ e.class }"
        return
      end

      # puts "debug1 accept a src"

      @src_infos[ src ] = {
        proxy_proto: :uncheck,   # :uncheck / :socks5
        proxy_type: :uncheck,    # :uncheck / :checking / :direct / :negotiation
        destination_domain: nil, # 目的地域名
        destination_port: nil,   # 目的地端口
        is_connect: true,        # 代理协议是http的场合，是否是CONNECT
        rbuff: '',               # 读到的流量
        dst: nil,                # 对应的dst
        wbuff: '',               # 从dst读到的流量
        created_at: Time.new,    # 创建时间
        last_recv_at: nil,       # 上一次收到新流量（由dst收到）的时间
        last_sent_at: nil,       # 上一次发出流量（由dst发出）的时间
        closing_write: false,    # 准备关闭写
        close_read: false,       # 已经关闭读
        close_write: false       # 已经关闭写
      }

      add_read( src, :src )
    end

    ##
    # read src
    #
    def read_src( src )
      if src.closed? then
        puts "p#{ Process.pid } #{ Time.new } read src but src closed?"
        return
      end

      begin
        data = src.read_nonblock( READ_SIZE )
      rescue IO::WaitReadable
        return
      rescue Errno::EINTR => e
        puts e.class
        return
      rescue Exception => e
        # puts "debug1 read src #{ e.class }"
        src_info = close_read_src( src )
        dst = src_info[ :dst ]

        if dst then
          set_dst_closing_write( dst )
        end

        return
      end

      src_info = @src_infos[ src ]
      proxy_type = src_info[ :proxy_type ]

      case proxy_type
      when :uncheck then
        if data[ 0 ].unpack( 'C' ).first != 5 then
          "p#{ Process.pid } #{ Time.new } unknown data #{ data.inspect }"
        end

        # puts "debug1 socks5 #{ data.inspect }"

        # https://tools.ietf.org/html/rfc1928
        #
        # +----+----------+----------+
        # |VER | NMETHODS | METHODS  |
        # +----+----------+----------+
        # | 1  |    1     | 1 to 255 |
        # +----+----------+----------+
        nmethods = data[ 1 ].unpack( 'C' ).first
        methods = data[ 2, nmethods ].unpack( 'C*' )

        unless methods.include?( 0 ) then
          puts "p#{ Process.pid } #{ Time.new } miss method 0x00"
          add_closing_src( src )
          return
        end

        # +----+--------+
        # |VER | METHOD |
        # +----+--------+
        # | 1  |   1    |
        # +----+--------+
        data2 = [ 5, 0 ].pack( 'CC' )
        add_src_wbuff( src, data2 )
        src_info[ :proxy_proto ] = :socks5
        src_info[ :proxy_type ] = :negotiation
      when :checking then
        # puts "debug1 add src rbuff before resolved #{ data.inspect }"
        src_info[ :rbuff ] << data
      when :negotiation then
        # +----+-----+-------+------+----------+----------+
        # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        # +----+-----+-------+------+----------+----------+
        # | 1  |  1  | X'00' |  1   | Variable |    2     |
        # +----+-----+-------+------+----------+----------+
        # puts "debug1 negotiation #{ data.inspect }"
        ver, cmd, rsv, atyp = data[ 0, 4 ].unpack( 'C4' )

        if cmd == 1 then
          # puts "debug1 socks5 CONNECT"

          if atyp == 1 then
            destination_host, destination_port = data[ 4, 6 ].unpack( 'Nn' )
            destination_addr = Socket.sockaddr_in( destination_port, destination_host )
            destination_addrinfo = Addrinfo.new( destination_addr )
            destination_ip = destination_addrinfo.ip_address
            src_info[ :destination_domain ] = destination_ip
            src_info[ :destination_port ] = destination_port
            # puts "debug1 IP V4 address #{ destination_addrinfo.ip_unpack.inspect }"
            new_a_dst( src, destination_addrinfo )
          elsif atyp == 3 then
            domain_len = data[ 4 ].unpack( 'C' ).first

            if ( domain_len + 7 ) == data.bytesize then
              domain = data[ 5, domain_len ]
              port = data[ ( 5 + domain_len ), 2 ].unpack( 'n' ).first
              src_info[ :destination_domain ] = domain
              src_info[ :destination_port ] = port
              # puts "debug1 DOMAINNAME #{ domain } #{ port }"
              resolve_domain( src, domain )
            end
          end
        else
          puts "p#{ Process.pid } #{ Time.new } socks5 cmd #{ cmd } not implement"
        end
      when :direct then
        dst = src_info[ :dst ]

        if dst then
          unless dst.closed? then
            # puts "debug2 add dst.wbuff #{ data.bytesize }"
            add_dst_wbuff( dst, data )
          end
        else
          # puts "debug1 dst not ready, save data to src.rbuff"
          add_src_rbuff( src, data )
        end
      end
    end

    ##
    # read dst
    #
    def read_dst( dst )
      if dst.closed? then
        puts "p#{ Process.pid } #{ Time.new } read dst but dst closed?"
        return
      end

      begin
        data = dst.read_nonblock( READ_SIZE )
      rescue IO::WaitReadable, Errno::EINTR
        print 'r'
        return
      rescue Exception => e
        # puts "debug1 read dst #{ e.class }"
        dst_info = close_read_dst( dst )
        src = dst_info[ :src ]
        set_src_closing_write( src )
        return
      end

      dst_info = @dst_infos[ dst ]
      src = dst_info[ :src ]
      add_src_wbuff( src, data )
    end

    ##
    # write src
    #
    def write_src( src )
      if src.closed? then
        puts "p#{ Process.pid } #{ Time.new } write src but src closed?"
        return
      end

      src_info = @src_infos[ src ]
      dst = src_info[ :dst ]
      data = src_info[ :wbuff ]

      # 写前为空，处理关闭写
      if data.empty? then
        if src_info[ :closing_write ] then
          close_write_src( src )
        else
          @writes.delete( src )
        end

        return
      end

      # 写入
      begin
        written = src.write_nonblock( data )
      rescue IO::WaitWritable, Errno::EINTR
        print 'w'
        return
      rescue Exception => e
        # puts "debug1 write src #{ e.class }"
        close_write_src( src )

        if dst then
          close_read_dst( dst )
        end

        return
      end

      # puts "debug2 written src #{ written }"
      data = data[ written..-1 ]
      src_info[ :wbuff ] = data
    end

    ##
    # write dst
    #
    def write_dst( dst )
      if dst.closed? then
        puts "p#{ Process.pid } #{ Time.new } write dst but dst closed?"
        return
      end

      dst_info = @dst_infos[ dst ]
      src = dst_info[ :src ]
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
        close_read_src( src )
        return
      end

      data = data[ written..-1 ]
      dst_info[ :wbuff ] = data

      unless src.closed? then
        src_info = @src_infos[ src ]
        src_info[ :last_sent_at ] = Time.new
      end
    end

  end
end
