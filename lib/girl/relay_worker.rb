module Girl
  class RelayWorker

    ##
    # initialize
    #
    def initialize( resolv_port, nameserver, resolvd_port, redir_port, proxyd_host, proxyd_port, directs, remotes, im )
      @nameserver_addr = Socket.sockaddr_in( 53, nameserver )
      @resolvd_ports = 10.times.map { | i | resolvd_port + i }
      @qnames = remotes.map { | dom | dom.split( '.' ).map{ | sub | [ sub.size ].pack( 'C' ) + sub }.join }
      @proxyd_host = proxyd_host
      @proxyd_port = proxyd_port
      @directs = directs
      @remotes = remotes
      @custom = Girl::ProxyCustom.new( im )
      @reads = []
      @writes = []
      @roles = {}                      # sock => :dotr / :resolv / :rsv / :redir / :proxy / :src / :dst / :atun / :btun
      @is_direct_caches = {}           # ip => true / false
      @src_infos = ConcurrentHash.new  # src => { :src_id, :addrinfo, :proxy_type, :destination_domain, :destination_port,
                                       #          :rbuff, :dst, :dst_created_at, :dst_connected, :ctl, :atun, :btun, :dst_id,
                                       #          :wbuff, :created_at, :pending, :last_recv_at, :last_sent_at, :closing_write, :closing, :paused }
      @dst_infos = ConcurrentHash.new  # dst => { :src, :domain, :wbuff, :closing_write, :paused }
      @atun_infos = ConcurrentHash.new # atun => { :src, :domain, :wbuff, :closing }
      @btun_infos = ConcurrentHash.new # btun => { :src, :domain, :wbuff, :rbuff, :paused }
      @rsv_infos = ConcurrentHash.new  # rsv => { :src_addr, :created_at }
      @local_addrinfos = Socket.ip_address_list

      new_a_pipe
      new_a_resolv( resolv_port )
      new_a_redir( redir_port )
    end

    ##
    # looping
    #
    def looping
      puts "#{ Time.new } looping"
      loop_check_state

      loop do
        rs, ws = IO.select( @reads, @writes )

        rs.each do | sock |
          role = @roles[ sock ]

          case role
          when :dotr then
            read_dotr( sock )
          when :resolv then
            read_resolv( sock )
          when :rsv then
            read_rsv( sock )
          when :redir then
            read_redir( sock )
          when :ctl then
            read_ctl( sock )
          when :src then
            read_src( sock )
          when :dst then
            read_dst( sock )
          when :atun then
            read_atun( sock )
          when :btun then
            read_btun( sock )
          else
            puts "#{ Time.new } read unknown role #{ role }"
            close_sock( sock )
          end
        end

        ws.each do | sock |
          role = @roles[ sock ]

          case role
          when :src then
            write_src( sock )
          when :dst then
            write_dst( sock )
          when :atun then
            write_atun( sock )
          when :btun then
            write_btun( sock )
          else
            puts "#{ Time.new } write unknown role #{ role }"
            close_sock( sock )
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
      # puts "debug exit"
      send_ctlmsg( [ CTL_FIN ].pack( 'C' ) )
      exit
    end

    private

    ##
    # add a new source
    #
    def add_a_new_source( src )
      src_info = @src_infos[ src ]

      if @ctl && !@ctl.closed? && @ctl_info[ :atund_addr ] then
        destination_domain = src_info[ :destination_domain ]
        destination_port = src_info[ :destination_port ]
        domain_port = [ destination_domain, destination_port ].join( ':' )
        # puts "debug add a new source #{ src_info[ :src_id ] } #{ domain_port }"
        key = [ A_NEW_SOURCE, src_info[ :src_id ] ].pack( 'CQ>' )
        add_ctlmsg( key, domain_port )
      else
        src_info[ :pending ] = true
      end
    end

    ##
    # add atun wbuff
    #
    def add_atun_wbuff( atun, data )
      return if atun.nil? || atun.closed?
      atun_info = @atun_infos[ atun ]
      atun_info[ :wbuff ] << data
      add_write( atun )

      if atun_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        src = atun_info[ :src ]

        if src then
          src_info = @src_infos[ src ]
          puts "#{ Time.new } pause remote src #{ src_info[ :destination_domain ].inspect }"
          @reads.delete( src )
          src_info[ :paused ] = true
        end
      end
    end

    ##
    # add ctlmsg
    #
    def add_ctlmsg( key, data )
      return if @ctl.nil? || @ctl.closed?
      ctlmsg = "#{ key }#{ data }"
      send_ctlmsg( ctlmsg )
      @ctl_info[ :resends ] << key
      loop_resend_ctlmsg( key, ctlmsg )
    end

    ##
    # add dst wbuff
    #
    def add_dst_wbuff( dst, data )
      return if dst.nil? || dst.closed?
      dst_info = @dst_infos[ dst ]
      dst_info[ :wbuff ] << data
      add_write( dst )

      if dst_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        src = dst_info[ :src ]

        if src then
          src_info = @src_infos[ src ]
          puts "#{ Time.new } pause direct src #{ src_info[ :destination_domain ].inspect }"
          @reads.delete( src )
          src_info[ :paused ] = true
        end
      end
    end

    ##
    # add read
    #
    def add_read( sock, role = nil )
      return if sock.nil? || sock.closed? || @reads.include?( sock )
      @reads << sock

      if role then
        @roles[ sock ] = role
      end

      next_tick
    end

    ##
    # add src rbuff
    #
    def add_src_rbuff( src, data )
      return if src.nil? || src.closed?
      src_info = @src_infos[ src ]
      return if src_info[ :closing ]
      src_info[ :rbuff ] << data

      if src_info[ :rbuff ].bytesize >= WBUFF_LIMIT then
        # puts "debug src.rbuff full"
        close_src( src )
      end
    end

    ##
    # add src wbuff
    #
    def add_src_wbuff( src, data )
      return if src.nil? || src.closed?
      src_info = @src_infos[ src ]
      return if src_info[ :closing ]
      src_info[ :wbuff ] << data
      src_info[ :last_recv_at ] = Time.new
      add_write( src )

      if src_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        dst = src_info[ :dst ]

        if dst then
          dst_info = @dst_infos[ dst ]

          if dst_info then
            puts "#{ Time.new } pause dst #{ dst_info[ :domain ].inspect }"
            @reads.delete( dst )
            dst_info[ :paused ] = true
          end
        else
          btun = src_info[ :btun ]

          if btun then
            btun_info = @btun_infos[ btun ]

            if btun_info then
              puts "#{ Time.new } pause btun #{ btun_info[ :domain ].inspect }"
              @reads.delete( btun )
              btun_info[ :paused ] = true
            end
          end
        end
      end
    end

    ##
    # add write
    #
    def add_write( sock )
      return if sock.nil? || sock.closed? || @writes.include?( sock )
      @writes << sock
    end

    ##
    # check has traffic
    #
    def check_has_traffic( src_info, expire_after )
      now = Time.new
      last_recv_at = src_info[ :last_recv_at ] || src_info[ :created_at ]
      last_sent_at = src_info[ :last_sent_at ] || src_info[ :created_at ]
      ( now - last_recv_at >= expire_after ) && ( now - last_sent_at >= expire_after )
    end

    ##
    # close atun
    #
    def close_atun( atun )
      return if atun.nil? || atun.closed?
      # puts "debug close atun"
      close_sock( atun )
      @atun_infos.delete( atun )
    end

    ##
    # close btun
    #
    def close_btun( btun )
      return if btun.nil? || btun.closed?
      # puts "debug close btun"
      close_sock( btun )
      @btun_infos.delete( btun )
    end

    ##
    # close ctl
    #
    def close_ctl( ctl )
      return if ctl.nil? || ctl.closed?
      close_sock( ctl )
    end

    ##
    # close dst
    #
    def close_dst( dst )
      return if dst.nil? || dst.closed?
      close_sock( dst )
      @dst_infos.delete( dst )
    end

    ##
    # close read dst
    #
    def close_read_dst( dst )
      return if dst.nil? || dst.closed?
      # puts "debug close read dst"
      dst.close_read
      @reads.delete( dst )

      if dst.closed? then
        # puts "debug dst closed"
        @writes.delete( dst )
        @roles.delete( dst )
        @dst_infos.delete( dst )
      end
    end

    ##
    # close read src
    #
    def close_read_src( src )
      return if src.nil? || src.closed?
      # puts "debug close read src"
      src.close_read
      @reads.delete( src )

      if src.closed? then
        # puts "debug src closed"
        @writes.delete( src )
        @roles.delete( src )
        @src_infos.delete( src )
      end
    end

    ##
    # close rsv
    #
    def close_rsv( rsv )
      return if rsv.nil? || rsv.closed?
      # puts "debug close rsv"
      close_sock( rsv )
      @rsv_infos.delete( rsv )
    end

    ##
    # close sock
    #
    def close_sock( sock )
      return if sock.nil? || sock.closed?
      sock.close
      @reads.delete( sock )
      @writes.delete( sock )
      @roles.delete( sock )
    end

    ##
    # close src
    #
    def close_src( src )
      return if src.nil? || src.closed?
      # puts "debug close src"
      close_sock( src )
      @src_infos.delete( src )
    end

    ##
    # close write dst
    #
    def close_write_dst( dst )
      return if dst.nil? || dst.closed?
      # puts "debug close write dst"
      dst.close_write
      @writes.delete( dst )

      if dst.closed? then
        # puts "debug dst closed"
        @reads.delete( dst )
        @roles.delete( dst )
        @dst_infos.delete( dst )
      end
    end

    ##
    # close write src
    #
    def close_write_src( src )
      return if src.nil? || src.closed?
      # puts "debug close write src"
      src.close_write
      @writes.delete( src )

      if src.closed? then
        # puts "debug src closed"
        @reads.delete( src )
        @roles.delete( src )
        @src_infos.delete( src )
      end
    end

    ##
    # loop check state
    #
    def loop_check_state
      Thread.new do
        loop do
          sleep CHECK_STATE_INTERVAL
          now = Time.new

          @src_infos.select{ | src, _ | !src.closed? }.each do | src, src_info |
            if src_info[ :dst ] then
              if src_info[ :dst_connected ] then
                is_expire = check_has_traffic( src_info, EXPIRE_AFTER )
              else
                is_expire = ( now - src_info[ :dst_created_at ] >= EXPIRE_CONNECTING )
              end
            elsif src_info[ :atun ] then
              is_expire = check_has_traffic( src_info, EXPIRE_AFTER )
            else
              is_expire = check_has_traffic( src_info, EXPIRE_NEW )
            end

            if is_expire then
              puts "#{ Time.new } expire src #{ src_info[ :addrinfo ].inspect } #{ src_info[ :destination_domain ].inspect } #{ src_info[ :destination_port ] }"
              src_info[ :closing ] = true
              next_tick
            elsif src_info[ :paused ] then
              dst = src_info[ :dst ]

              if dst then
                dst_info = @dst_infos[ dst ]

                if dst_info[ :wbuff ].bytesize < RESUME_BELOW then
                  puts "#{ Time.new } resume direct src #{ src_info[ :destination_domain ].inspect }"
                  add_read( src )
                  src_info[ :paused ] = false
                end
              else
                atun = src_info[ :atun ]

                if atun && !atun.closed? then
                  atun_info = @atun_infos[ atun ]

                  if atun_info[ :wbuff ].bytesize < RESUME_BELOW then
                    puts "#{ Time.new } resume remote src #{ src_info[ :destination_domain ].inspect }"
                    add_read( src )
                    src_info[ :paused ] = false
                  end
                end
              end
            end
          end

          @dst_infos.select{ | dst, info | !dst.closed? && info[ :paused ] }.each do | dst, dst_info |
            src = dst_info[ :src ]

            if src && !src.closed? then
              src_info = @src_infos[ src ]

              if src_info[ :wbuff ].bytesize < RESUME_BELOW then
                puts "#{ Time.new } resume dst #{ dst_info[ :domain ].inspect }"
                add_read( dst )
                dst_info[ :paused ] = false
              end
            end
          end

          @btun_infos.select{ | btun, info | !btun.closed? && info[ :paused ] }.each do | btun, btun_info |
            src = btun_info[ :src ]

            if src && !src.closed? then
              src_info = @src_infos[ src ]

              if src_info[ :wbuff ].bytesize < RESUME_BELOW then
                puts "#{ Time.new } resume btun #{ btun_info[ :domain ].inspect }"
                add_read( btun )
                btun_info[ :paused ] = false
              end
            end
          end

          @rsv_infos.select{ | rsv, info | !rsv.closed? && ( now - info[ :created_at ] >= EXPIRE_NEW ) }.values.each do | rsv_info |
            puts "#{ Time.new } expire rsv"
            rsv_info[ :closing ] = true
            next_tick
          end
        end
      end
    end

    ##
    # loop resend ctlmsg
    #
    def loop_resend_ctlmsg( key, ctlmsg )
      Thread.new do
        resending = true

        RESEND_LIMIT.times do
          sleep RESEND_INTERVAL

          if @ctl && !@ctl.closed? && @ctl_info[ :resends ].include?( key ) then
            puts "#{ Time.new } resend #{ ctlmsg.inspect }"
            send_ctlmsg( ctlmsg )
          else
            resending = false
          end

          break unless resending
        end

        if resending then
          set_ctl_closing
        end
      end
    end

    ##
    # new a ctl
    #
    def new_a_ctl
      ctl = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      ctld_port = @proxyd_port + 10.times.to_a.sample
      ctld_addr = Socket.sockaddr_in( ctld_port, @proxyd_host )
      @ctl = ctl

      @ctl_info = {
        ctld_addr: ctld_addr, # ctld地址
        resends: [],          # 重传的key
        atund_addr: nil,      # atund地址
        btund_addr: nil,      # btund地址
        closing: false        # 准备关闭
      }

      add_read( ctl, :ctl )
      hello = @custom.hello
      puts "#{ Time.new } hello i'm #{ hello.inspect } #{ ctld_port }"
      add_ctlmsg( [ HELLO ].pack( 'C' ), hello )
    end

    ##
    # new a dst
    #
    def new_a_dst( addrinfo, src )
      return if src.nil? || src.closed?
      src_info = @src_infos[ src ]
      domain = src_info[ :destination_domain ]
      port = src_info[ :destination_port ]
      ip = addrinfo.ip_address
      destination_addr = Socket.sockaddr_in( port, ip )

      begin
        dst = Socket.new( addrinfo.ipv4? ? Socket::AF_INET : Socket::AF_INET6, Socket::SOCK_STREAM, 0 )
      rescue Exception => e
        puts "#{ Time.new } new a dst #{ e.class } #{ domain.inspect } #{ ip } #{ port }"
        close_src( src )
        return
      end

      dst.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )

      begin
        dst.connect_nonblock( destination_addr )
      rescue IO::WaitWritable
      rescue Exception => e
        puts "#{ Time.new } dst connect destination #{ e.class } #{ domain.inspect  } #{ ip } #{ port }"
        dst.close
        close_src( src )
        return
      end

      # puts "debug a new dst #{ dst.local_address.inspect }"
      dst_info = {
        src: src,             # 对应src
        domain: domain,       # 目的地
        wbuff: '',            # 写前
        closing_write: false, # 准备关闭写
        paused: false         # 是否已暂停
      }

      @dst_infos[ dst ] = dst_info
      src_info[ :proxy_type ] = :direct
      src_info[ :dst ] = dst
      src_info[ :dst_created_at ] = Time.new

      if src_info[ :rbuff ] then
        # puts "debug move src.rbuff to dst.wbuff"
        dst_info[ :wbuff ] << src_info[ :rbuff ]
      end

      add_read( dst, :dst )
      add_write( dst )
    end

    ##
    # new a pipe
    #
    def new_a_pipe
      dotr, dotw = IO.pipe
      @dotw = dotw
      add_read( dotr, :dotr )
    end

    ##
    # new a redir
    #
    def new_a_redir( redir_port )
      redir = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      redir.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      redir.bind( Socket.sockaddr_in( redir_port, '0.0.0.0' ) )
      redir.listen( 127 )
      puts "#{ Time.new } redir listen on #{ redir_port }"
      add_read( redir, :redir )
      @redir_port = redir_port
      @redir_local_address = redir.local_address
    end

    ##
    # new a remote
    #
    def new_a_remote( src )
      return if src.nil? || src.closed?
      src_info = @src_infos[ src ]
      src_info[ :proxy_type ] = :remote
      add_a_new_source( src )
    end

    ##
    # new a resolv
    #
    def new_a_resolv( resolv_port )
      resolv = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      resolv.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      resolv.bind( Socket.sockaddr_in( resolv_port, '0.0.0.0' ) )

      puts "#{ Time.new } resolv bind on #{ resolv_port }"
      add_read( resolv, :resolv )
      @resolv = resolv
    end

    ##
    # new a rsv
    #
    def new_a_rsv( src_addr, data )
      rsv = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      rsv.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )

      if @qnames.any?{ | qname | data.include?( qname ) } then
        data = @custom.encode( data )
        to_addr = Socket.sockaddr_in( @resolvd_ports.sample, @proxyd_host )
      else
        to_addr = @nameserver_addr
      end

      # puts "debug new a rsv to #{ Addrinfo.new( to_addr ).inspect }"

      @rsv_infos[ rsv ] = {
        src_addr: src_addr,
        created_at: Time.new,
        closing: false
      }

      add_read( rsv, :rsv )
      send_data( rsv, to_addr, data )
    end

    ##
    # new a tunnel
    #
    def new_a_tunnel( addrinfo, src )
      return if src.nil? || src.closed?
      src_info = @src_infos[ src ]
      ip = addrinfo.ip_address
      port = src_info[ :destination_port ]

      if ( @local_addrinfos.any?{ | _addrinfo | _addrinfo.ip_address == ip } ) && ( port == @redir_port ) then
        puts "#{ Time.new } ignore #{ ip }:#{ port }"
        close_src( src )
        return
      end

      if ( src_info[ :destination_domain ] == @proxyd_host ) && ![ 80, 443 ].include?( port ) then
        # 访问远端非80/443端口，直连
        puts "#{ Time.new } direct #{ ip } #{ port }"
        new_a_dst( addrinfo, src )
        return
      end

      if @is_direct_caches.include?( ip ) then
        is_direct = @is_direct_caches[ ip ]
      else
        is_direct = @directs.any?{ | direct | direct.include?( ip ) }
        puts "#{ Time.new } cache is direct #{ ip } #{ is_direct }"
        @is_direct_caches[ ip ] = is_direct
      end

      if is_direct then
        # puts "debug #{ addrinfo.inspect } hit directs"
        new_a_dst( addrinfo, src )
      else
        # puts "debug #{ addrinfo.inspect } go remote"
        new_a_remote( src )
      end
    end

    ##
    # new tuns
    #
    def new_tuns( src_id, dst_id )
      src, src_info = @src_infos.find{ | _, info | ( info[ :src_id ] == src_id ) && info[ :dst_id ].nil? }
      return if src.nil? || src.closed?

      # puts "debug new atun and btun"
      atun = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      atun.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )

      begin
        atun.connect_nonblock( @ctl_info[ :atund_addr ] )
      rescue IO::WaitWritable
      rescue Exception => e
        puts "#{ Time.new } connect atund #{ e.class }"
        atun.close
        return
      end

      btun = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      btun.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )

      begin
        btun.connect_nonblock( @ctl_info[ :btund_addr ] )
      rescue IO::WaitWritable
      rescue Exception => e
        puts "#{ Time.new } connect btund #{ e.class }"
        btun.close
        return
      end

      domain = src_info[ :destination_domain ]
      atun_wbuff = [ dst_id ].pack( 'n' )

      until src_info[ :rbuff ].empty? do
        data = src_info[ :rbuff ][ 0, CHUNK_SIZE ]
        data_size = data.bytesize
        # puts "debug move src.rbuff #{ data_size } to atun.wbuff"
        atun_wbuff << pack_a_chunk( data )
        src_info[ :rbuff ] = src_info[ :rbuff ][ data_size..-1 ]
      end

      @atun_infos[ atun ] = {
        src: src,          # 对应src
        domain: domain,    # 目的地
        wbuff: atun_wbuff, # 写前
        closing: false     # 准备关闭
      }

      btun_wbuff = [ dst_id ].pack( 'n' )

      @btun_infos[ btun ] = {
        src: src,          # 对应src
        domain: domain,    # 目的地
        wbuff: btun_wbuff, # 写前
        rbuff: '',         # 暂存当前块没收全的流量
        paused: false      # 是否已暂停
      }

      src_info[ :dst_id ] = dst_id
      src_info[ :atun ] = atun
      src_info[ :btun ] = btun
      add_read( atun, :atun )
      add_read( btun, :btun )
      add_write( atun )
      add_write( btun )
    end

    ##
    # next tick
    #
    def next_tick
      @dotw.write( '.' )
    end

    ##
    # pack a chunk
    #
    def pack_a_chunk( data )
      data = @custom.encode( data )
      "#{ [ data.bytesize ].pack( 'n' ) }#{ data }"
    end

    ##
    # send ctlmsg
    #
    def send_ctlmsg( data )
      return if @ctl.nil? || @ctl.closed?
      data = @custom.encode( data )

      begin
        @ctl.sendmsg_nonblock( data, 0, @ctl_info[ :ctld_addr ] )
      rescue Exception => e
        puts "#{ Time.new } ctl sendmsg #{ e.class }"
        set_ctl_closing
      end
    end

    ##
    # send data
    #
    def send_data( sock, to_addr, data )
      begin
        sock.sendmsg_nonblock( data, 0, to_addr )
      rescue Exception => e
        puts "#{ Time.new } sendmsg #{ e.class } #{ to_addr.inspect }"
      end
    end

    ##
    # set atun closing
    #
    def set_atun_closing( atun )
      return if atun.nil? || atun.closed?
      atun_info = @atun_infos[ atun ]
      return if atun_info[ :closing ]
      # puts "debug set atun closing"
      atun_info[ :closing ] = true
      add_write( atun )
    end

    ##
    # set ctl closing
    #
    def set_ctl_closing
      return if @ctl.nil? || @ctl.closed? || @ctl_info[ :closing ]
      @ctl_info[ :closing ] = true
      next_tick
    end

    ##
    # set dst closing write
    #
    def set_dst_closing_write( dst )
      return if dst.nil? || dst.closed?
      dst_info = @dst_infos[ dst ]
      return if dst_info[ :closing_write ]
      # puts "debug set dst closing write"
      dst_info[ :closing_write ] = true
      add_write( dst )
    end

    ##
    # set src closing write
    #
    def set_src_closing_write( src )
      return if src.nil? || src.closed?
      src_info = @src_infos[ src ]
      return if src_info[ :closing ] || src_info[ :closing_write ]
      src_info[ :closing_write ] = true
      add_write( src )
    end

    ##
    # read dotr
    #
    def read_dotr( dotr )
      dotr.read_nonblock( READ_SIZE )
      @rsv_infos.select{ | _, info | info[ :closing ] }.keys.each{ | rsv | close_rsv( rsv ) }

      if @ctl && !@ctl.closed? && @ctl_info[ :closing ] then
        send_ctlmsg( [ CTL_FIN ].pack( 'C' ) )
        close_ctl( @ctl )
      end

      @src_infos.select{ | _, info | info[ :closing ] }.keys.each do | src |
        src_info = close_src( src )

        if src_info then
          dst = src_info[ :dst ]

          if dst then
            close_dst( dst )
          else
            close_atun( src_info[ :atun ] )
            close_btun( src_info[ :btun ] )
          end
        end
      end
    end

    ##
    # read resolv
    #
    def read_resolv( resolv )
      data, addrinfo, rflags, *controls = resolv.recvmsg
      # puts "debug resolv recvmsg #{ addrinfo.ip_unpack.inspect } #{ data.inspect }"
      new_a_rsv( addrinfo, data )
    end

    ##
    # read rsv
    #
    def read_rsv( rsv )
      if rsv.closed? then
        puts "#{ Time.new } read rsv but rsv closed?"
        return
      end

      begin
        data, addrinfo, rflags, *controls = rsv.recvmsg
      rescue Exception => e
        puts "#{ Time.new } rsv recvmsg #{ e.class }"
        close_rsv( rsv )
        return
      end

      # puts "debug rsv recvmsg #{ addrinfo.ip_unpack.inspect } #{ data.inspect }"

      if addrinfo.ip_address == @proxyd_host then
        data = @custom.decode( data )
      end

      rsv_info = @rsv_infos[ rsv ]
      send_data( @resolv, rsv_info[ :src_addr ], data )
      close_rsv( rsv )
    end

    ##
    # read redir
    #
    def read_redir( redir )
      begin
        src, addrinfo = redir.accept_nonblock
      rescue IO::WaitReadable, Errno::EINTR => e
        puts "accept #{ e.class }"
        return
      end

      begin
        # /usr/include/linux/netfilter_ipv4.h
        option = src.getsockopt( Socket::SOL_IP, 80 )
      rescue Exception => e
        puts "get SO_ORIGINAL_DST #{ e.class }"
        src.close
      end

      dest_family, dest_port, dest_host = option.unpack( 'nnN' )
      dest_addr = Socket.sockaddr_in( dest_port, dest_host )
      dest_addrinfo = Addrinfo.new( dest_addr )
      dest_ip = dest_addrinfo.ip_address

      src_id = rand( ( 2 ** 64 ) - 2 ) + 1
      # puts "debug accept a src #{ addrinfo.ip_unpack.inspect } to #{ dest_ip }:#{ dest_port } #{ src_id }"

      @src_infos[ src ] = {
        src_id: src_id,              # src_id
        addrinfo: addrinfo,          # addrinfo
        proxy_type: :checking,       # :checking / :direct / :tunnel
        destination_domain: dest_ip, # 目的地域名
        destination_port: dest_port, # 目的地端口
        rbuff: '',                   # 读到的流量
        dst: nil,                    # :direct的场合，对应的dst
        dst_created_at: nil,         # :direct的场合，对应的dst的创建时间
        dst_connected: false,        # :direct的场合，对应的dst是否已连接
        ctl: nil,                    # :tunnel的场合，对应的ctl
        atun: nil,                   # :tunnel的场合，对应的atun
        btun: nil,                   # :tunnel的场合，对应的btun
        dst_id: nil,                 # 远端dst id
        wbuff: '',                   # 从dst/btun读到的流量
        created_at: Time.new,        # 创建时间
        pending: false,              # 是否在收到TUND_PORT时补发A_NEW_SOURCE
        last_recv_at: nil,           # 上一次收到新流量（由dst收到，或者由tun收到）的时间
        last_sent_at: nil,           # 上一次发出流量（由dst发出，或者由tun发出）的时间
        closing_write: false,        # 准备关闭写
        closing: false,              # 准备关闭
        paused: false                # 是否暂停
      }

      add_read( src, :src )

      if @ctl.nil? || @ctl.closed? then
        new_a_ctl
      end

      new_a_tunnel( dest_addrinfo, src )
    end

    ##
    # read ctl
    #
    def read_ctl( ctl )
      begin
        data, addrinfo, rflags, *controls = ctl.recvmsg
      rescue Exception => e
        puts "#{ Time.new } ctl recvmsg #{ e.class }"
        close_ctl( ctl )
        return
      end

      data = @custom.decode( data )
      ctl_num = data[ 0 ].unpack( 'C' ).first

      case ctl_num
      when TUND_PORT then
        return if @ctl_info[ :atund_addr ] || data.bytesize != 5
        atund_port, btund_port = data[ 1, 4 ].unpack( 'nn' )
        puts "#{ Time.new } got tund port #{ atund_port } #{ btund_port }"
        @ctl_info[ :resends ].delete( [ HELLO ].pack( 'C' ) )
        @ctl_info[ :atund_addr ] = Socket.sockaddr_in( atund_port, @proxyd_host )
        @ctl_info[ :btund_addr ] = Socket.sockaddr_in( btund_port, @proxyd_host )

        @src_infos.select{ | src, info | info[ :pending ] }.each do | src, src_info |
          add_a_new_source( src )
          src_info[ :pending ] = false
        end
      when PAIRED then
        return if data.bytesize != 11 || @ctl_info[ :atund_addr ].nil? || @ctl_info[ :btund_addr ].nil?
        src_id, dst_id = data[ 1, 10 ].unpack( 'Q>n' )
        # puts "debug got paired #{ src_id } #{ dst_id }"
        @ctl_info[ :resends ].delete( [ A_NEW_SOURCE, src_id ].pack( 'CQ>' ) )
        new_tuns( src_id, dst_id )
      when UNKNOWN_CTL_ADDR then
        puts "#{ Time.new } got unknown ctl addr"
        close_ctl( ctl )
        new_a_ctl
      end
    end

    ##
    # read src
    #
    def read_src( src )
      if src.closed? then
        puts "#{ Time.new } read src but src closed?"
        return
      end

      src_info = @src_infos[ src ]

      begin
        data = src.read_nonblock( CHUNK_SIZE )
      rescue Exception => e
        # puts "debug read src #{ e.class }"
        close_read_src( src )
        dst = src_info[ :dst ]

        if dst then
          set_dst_closing_write( dst )
        else
          set_atun_closing( src_info[ :atun ] )
        end

        return
      end

      proxy_type = src_info[ :proxy_type ]

      case proxy_type
      when :checking then
        # puts "debug add src rbuff before resolved #{ data.inspect }"
        src_info[ :rbuff ] << data
      when :remote then
        atun = src_info[ :atun ]

        if atun then
          add_atun_wbuff( atun, pack_a_chunk( data ) )
        else
          # puts "debug add src.rbuff #{ data.bytesize }"
          add_src_rbuff( src, data )
        end
      when :direct then
        dst = src_info[ :dst ]

        if dst then
          add_dst_wbuff( dst, data )
        else
          # puts "debug add src.rbuff #{ data.bytesize }"
          add_src_rbuff( src, data )
        end
      end
    end

    ##
    # read dst
    #
    def read_dst( dst )
      if dst.closed? then
        puts "#{ Time.new } read dst but dst closed?"
        return
      end

      dst_info = @dst_infos[ dst ]
      src = dst_info[ :src ]

      begin
        data = dst.read_nonblock( CHUNK_SIZE )
      rescue Exception => e
        # puts "debug read dst #{ e.class }"
        close_read_dst( dst )
        set_src_closing_write( src )
        return
      end

      add_src_wbuff( src, data )
    end

    ##
    # read atun
    #
    def read_atun( atun )
      if atun.closed? then
        puts "#{ Time.new } read atun but atun closed?"
        return
      end

      atun_info = @atun_infos[ atun ]
      src = atun_info[ :src ]

      begin
        data = atun.read_nonblock( READ_SIZE )
      rescue Exception => e
        # puts "debug read atun #{ e.class }"
        close_atun( atun )
        close_read_src( src )
        return
      end

      # puts "debug unexpect data?"
    end

    ##
    # read btun
    #
    def read_btun( btun )
      if btun.closed? then
        puts "#{ Time.new } read btun but btun closed?"
        return
      end

      btun_info = @btun_infos[ btun ]
      src = btun_info[ :src ]

      begin
        data = btun.read_nonblock( READ_SIZE )
      rescue Exception => e
        # puts "debug read btun #{ e.class }"
        close_btun( btun )
        set_src_closing_write( src )
        return
      end

      data = "#{ btun_info[ :rbuff ] }#{ data }"

      loop do
        if data.bytesize <= 2 then
          btun_info[ :rbuff ] = data
          break
        end

        len = data[ 0, 2 ].unpack( 'n' ).first

        if len == 0 then
          puts "#{ Time.new } zero traffic len?"
          close_btun( btun )
          close_src( src )
          return
        end

        chunk = data[ 2, len ]

        if chunk.bytesize < len then
          btun_info[ :rbuff ] = data
          break
        end

        chunk = @custom.decode( chunk )
        add_src_wbuff( src, chunk )
        data = data[ ( 2 + len )..-1 ]
      end
    end

    ##
    # write src
    #
    def write_src( src )
      if src.closed? then
        puts "#{ Time.new } write src but src closed?"
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
        # puts "debug write src #{ e.class }"
        close_write_src( src )

        if dst then
          close_read_dst( dst )
        else
          close_btun( src_info[ :btun ] )
        end

        return
      end

      data = data[ written..-1 ]
      src_info[ :wbuff ] = data
    end

    ##
    # write dst
    #
    def write_dst( dst )
      if dst.closed? then
        puts "#{ Time.new } write dst but dst closed?"
        return
      end

      dst_info = @dst_infos[ dst ]
      src = dst_info[ :src ]
      src_info = @src_infos[ src ]

      if src && !src.closed? then
        src_info[ :dst_connected ] = true
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
        # puts "debug write dst #{ e.class }"
        close_write_dst( dst )
        close_read_src( src )
        return
      end

      data = data[ written..-1 ]
      dst_info[ :wbuff ] = data

      if src && !src.closed? then
        src_info[ :last_sent_at ] = Time.new
      end
    end

    ##
    # write atun
    #
    def write_atun( atun )
      if atun.closed? then
        puts "#{ Time.new } write atun but atun closed?"
        return
      end

      atun_info = @atun_infos[ atun ]
      src = atun_info[ :src ]
      data = atun_info[ :wbuff ]

      # 写前为空，处理关闭写
      if data.empty? then
        if atun_info[ :closing ] then
          close_atun( atun )
        else
          @writes.delete( atun )
        end

        return
      end

      # 写入
      begin
        written = atun.write_nonblock( data )
      rescue Exception => e
        # puts "debug write atun #{ e.class }"
        close_atun( atun )
        close_read_src( src )
        return
      end

      data = data[ written..-1 ]
      atun_info[ :wbuff ] = data

      if src && !src.closed? then
        src_info = @src_infos[ src ]
        src_info[ :last_sent_at ] = Time.new
      end
    end

    ##
    # write btun
    #
    def write_btun( btun )
      if btun.closed? then
        puts "#{ Time.new } write btun but btun closed?"
        return
      end

      btun_info = @btun_infos[ btun ]
      data = btun_info[ :wbuff ]

      # 写入dst id
      begin
        written = btun.write( data )
      rescue Exception => e
        # puts "debug write btun #{ e.class }"
        src = btun_info[ :src ]
        close_btun( btun )
        close_src( src )
        return
      end

      @writes.delete( btun )
    end

  end
end
