module Girl
  class ProxyWorker2
    include Dns

    def initialize(
      redir_port,
      memd_port,
      tspd_port,
      proxyd_host,
      proxyd_port,
      nameservers,
      im,
      directs,
      remotes,
      head_len,
      h_a_new_source,
      h_dst_close,
      h_query,
      h_response,
      h_src_close,
      h_traffic,
      expire_connecting,
      expire_long_after,
      expire_short_after,
      is_debug,
      is_client_fastopen,
      is_server_fastopen )

      @proxyd_host = proxyd_host
      @proxyd_addr = Socket.sockaddr_in( proxyd_port, proxyd_host )
      @nameserver_addrs = nameservers.map{ | n | Socket.sockaddr_in( 53, n ) }
      @im = im
      @local_ips = Socket.ip_address_list.select{ | info | info.ipv4? }.map{ | info | info.ip_address }
      @update_roles = [ :dns, :dst, :mem, :src, :rsv ] # 参与淘汰的角色
      @updates_limit = 1010  # 淘汰池上限，1015(mac) - [ memd, proxy, redir, rsvd, tspd ]
      @eliminate_count = 0   # 淘汰次数
      @directs = directs
      @remotes = remotes
      @reads = []            # 读池
      @writes = []           # 写池
      @roles = {}            # sock =>  :dns / :dst / :mem / :memd / :proxy / :redir / :rsv / :rsvd / :src / :tspd
      @updates = {}          # sock => updated_at
      @proxy_infos = {}      # proxy => { :im :in :is_syn :out :overflow_domains :pause_domains :rbuff :srcs :wbuff }
      @mem_infos = {}        # mem => { :wbuff }
      @src_infos = {}        # src => { :addrinfo :closing :destination_domain :destination_port :dst :is_connect :paused :proxy_proto :proxy_type :rbuff :src_id :wbuff }
      @dst_infos = {}        # dst => { :closing :connected :domain :ip :paused :port :src :wbuff }
      @dns_infos = {}        # dns => { :domain :src }
      @rsv_infos = {}        # rsv => { :addrinfo :domain :type }
      @near_infos = {}       # near_id => { :addrinfo :created_at :domain :id :type }
      @resolv_caches = {}    # domain => [ ip, created_at ]
      @is_direct_caches = {} # ip => true / false
      @response_caches = {}  # domain => [ response, created_at, ip, is_remote ]
      @response6_caches = {} # domain => [ response, created_at, ip, is_remote ]
      @head_len = head_len
      @h_a_new_source = h_a_new_source
      @h_dst_close = h_dst_close
      @h_query = h_query
      @h_response = h_response
      @h_src_close = h_src_close
      @h_traffic = h_traffic
      @expire_connecting = expire_connecting
      @expire_long_after = expire_long_after
      @expire_short_after = expire_short_after
      @is_debug = is_debug
      @is_client_fastopen = is_client_fastopen
      @is_server_fastopen = is_server_fastopen

      new_a_redir( redir_port )
      new_a_memd( memd_port )
      new_a_rsvd( tspd_port )
      new_a_tspd( tspd_port )
    end

    def looping
      puts "looping"

      loop do
        rs, ws = IO.select( @reads, @writes )

        rs.each do | sock |
          role = @roles[ sock ]

          case role
          when :dns then
            read_dns( sock )
          when :dst then
            read_dst( sock )
          when :mem then
            read_mem( sock )
          when :memd then
            read_memd( sock )
          when :proxy then
            read_proxy( sock )
          when :redir then
            read_redir( sock )
          when :rsv then
            read_rsv( sock )
          when :rsvd then
            read_rsvd( sock )
          when :src then
            read_src( sock )
          when :tspd then
            read_tspd( sock )
          else
            close_sock( sock )
          end
        end

        ws.each do | sock |
          role = @roles[ sock ]

          case role
          when :dst then
            write_dst( sock )
          when :mem then
            write_mem( sock )
          when :proxy then
            write_proxy( sock )
          when :src then
            write_src( sock )
          else
            close_sock( sock )
          end
        end
      end
    rescue Interrupt => e
      puts e.class
      quit!
    end

    def quit!
      exit
    end

    private

    def add_dst_wbuff( dst, data )
      return if dst.nil? || dst.closed? || data.empty?
      dst_info = @dst_infos[ dst ]
      dst_info[ :wbuff ] << data
      add_write( dst )
      return if dst.closed?

      if dst_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        src = dst_info[ :src ]

        if src && !src.closed? then
          src_info = @src_infos[ src ]
          puts "pause direct src #{ src_info[ :destination_domain ] }"
          @reads.delete( src )
          src_info[ :paused ] = true
        end
      end
    end

    def add_mem_wbuff( mem, data )
      return if mem.nil? || mem.closed? || data.empty?
      mem_info = @mem_infos[ mem ]
      mem_info[ :wbuff ] << data
      add_write( mem )
    end

    def add_read( sock, role = nil )
      return if sock.nil? || sock.closed? || @reads.include?( sock )
      @reads << sock

      if role then
        @roles[ sock ] = role
      else
        role = @roles[ sock ]
      end

      if @update_roles.include?( role ) then
        set_update( sock )
      end
    end

    def add_socks5_conn_reply( src )
      # +----+-----+-------+------+----------+----------+
      # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
      # +----+-----+-------+------+----------+----------+
      # | 1  |  1  | X'00' |  1   | Variable |    2     |
      # +----+-----+-------+------+----------+----------+
      redir_ip, redir_port = @redir_local_address.ip_unpack
      data = [ [ 5, 0, 0, 1 ].pack( 'C4' ), IPAddr.new( redir_ip ).hton, [ redir_port ].pack( 'n' ) ].join
      add_src_wbuff( src, data )
    end

    def add_src_rbuff( src, data )
      return if src.nil? || src.closed? || data.empty?
      src_info = @src_infos[ src ]
      puts "add src rbuff #{ data.bytesize }" if @is_debug
      src_info[ :rbuff ] << data

      if src_info[ :rbuff ].bytesize >= WBUFF_LIMIT then
        puts "src rbuff full"
        close_src( src )
      end
    end

    def add_src_wbuff( src, data )
      return if src.nil? || src.closed? || data.empty?
      src_info = @src_infos[ src ]
      src_info[ :wbuff ] << data
      add_write( src )

      if !src.closed? && src_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        dst = src_info[ :dst ]

        if dst then
          dst_info = @dst_infos[ dst ]

          if dst_info then
            puts "overflow #{ src_info[ :destination_domain ] }, pause dst"
            @reads.delete( dst )
            dst_info[ :paused ] = true
          end
        elsif @proxy then
          if @proxy.closed? then
            close_src( src )
            return
          end

          proxy_info = @proxy_infos[ @proxy ]
          puts "overflow #{ src_info[ :destination_domain ] }, pause proxy"
          @reads.delete( @proxy )
          proxy_info[ :overflow_domains ][ src ] = src_info[ :destination_domain ]
        end
      end
    end

    def add_proxy_wbuff( data )
      return if data.empty?

      if @proxy.nil? || @proxy.closed? then
        proxy_info = new_a_proxy
        puts "im #{ @im }"
        head = ''
        chars = []
        @head_len.times{ chars << rand( 256 ) }
        head = chars.pack( 'C*' )
        head << "#{ [ @im.bytesize ].pack( 'C' ) }#{ @im }"
        proxy_info[ :wbuff ] << head
      else
        proxy_info = @proxy_infos[ @proxy ]
      end

      proxy_info[ :wbuff ] << data
      add_write( @proxy )
    end

    def add_write( sock )
      return if sock.nil? || sock.closed? || @writes.include?( sock )
      @writes << sock
      role = @roles[ sock ]

      if @update_roles.include?( role ) then
        set_update( sock )
      end
    end

    def close_dns( dns )
      return nil if dns.nil? || dns.closed?
      close_sock( dns )
      dns_info = @dns_infos.delete( dns )
      puts "close dns #{ dns_info[ :domain ] }" if @is_debug
      dns_info
    end

    def close_dst( dst )
      return nil if dst.nil? || dst.closed?
      close_sock( dst )
      dst_info = @dst_infos.delete( dst )
      puts "close dst #{ dst_info[ :domain ] } #{ dst_info[ :port ] }" if @is_debug
      set_src_closing( dst_info[ :src ] ) if dst_info
      dst_info
    end

    def close_mem( mem )
      return nil if mem.nil? || mem.closed?
      close_sock( mem )
      @mem_infos.delete( mem )
    end

    def close_proxy( proxy )
      return if proxy.nil? || proxy.closed?
      close_sock( proxy )
      proxy_info = @proxy_infos.delete( proxy )
      puts "close proxy" if @is_debug
      proxy_info[ :srcs ].values.each{ | src | set_src_closing( src ) }
      proxy_info
    end

    def close_rsv( rsv )
      return nil if rsv.nil? || rsv.closed?
      close_sock( rsv )
      rsv_info = @rsv_infos.delete( rsv )
      puts "close rsv #{ rsv_info[ :domain ] }" if @is_debug
      rsv_info
    end

    def close_sock( sock )
      return if sock.nil? || sock.closed?
      sock.close
      @reads.delete( sock )
      @writes.delete( sock )
      @updates.delete( sock )
      @roles.delete( sock )
    end

    def close_src( src )
      return nil if src.nil? || src.closed?
      close_sock( src )
      src_info = @src_infos.delete( src )
      puts "close src #{ src_info[ :destination_domain ] } #{ src_info[ :destination_port ] }" if @is_debug
      dst = src_info[ :dst ]

      if dst then
        set_dst_closing( dst )
      elsif @proxy && !@proxy.closed? then
        proxy_info = @proxy_infos[ @proxy ]
        src_id = src_info[ :src_id ]

        if proxy_info[ :srcs ].delete( src_id ) then
          puts "add h_src_close #{ src_id }" if @is_debug
          msg = "#{ @h_src_close }#{ [ src_id ].pack( 'Q>' ) }"
          add_proxy_wbuff( pack_a_chunk( msg ) )
        end
      end

      src_info
    end

    def deal_msg( data, proxy )
      return if data.nil? || data.empty? || proxy.nil? || proxy.closed?
      proxy_info = @proxy_infos[ proxy ]
      h = data[ 0 ]

      case h
      when @h_traffic then
        return if data.bytesize < 3
        src_id = data[ 1, 8 ].unpack( 'Q>' ).first
        data = data[ 9..-1 ]
        # puts "got h_traffic #{ src_id } #{ data.bytesize }" if @is_debug
        src = proxy_info[ :srcs ][ src_id ]
        add_src_wbuff( src, data )
      when @h_dst_close then
        return if data.bytesize < 9
        src_id = data[ 1, 8 ].unpack( 'Q>' ).first
        puts "got h_dst_close #{ src_id }" if @is_debug
        src = proxy_info[ :srcs ].delete( src_id )
        set_src_closing( src )
      when @h_response then
        return if data.bytesize < 3
        near_id = data[ 1, 8 ].unpack( 'Q>' ).first
        data = data[ 9..-1 ]
        puts "got h_response #{ near_id } #{ data.bytesize }" if @is_debug
        near_info = @near_infos.delete( near_id )

        if near_info then
          data[ 0, 2 ] = near_info[ :id ]
          addrinfo = near_info[ :addrinfo ]
          send_data( @rsvd, data, addrinfo )

          begin
            ip = seek_ip( data )
          rescue Exception => e
            puts "response seek ip #{ e.class } #{ e.message }"
          end

          if ip then
            domain = near_info[ :domain ]
            type = near_info[ :type ]

            if type == 1 then
              @response_caches[ domain ] = [ data, Time.new, ip, true ]
            else
              @response6_caches[ domain ] = [ data, Time.new, ip, true ]
            end
          end
        end
      end
    end

    def decode_to_msgs( data )
      msgs = []
      part = ''

      loop do
        if data.bytesize <= 2 then
          part = data
          break
        end

        len = data[ 0, 2 ].unpack( 'n' ).first

        if len == 0 then
          puts "msg zero len?"
          break
        end

        if data.bytesize < ( 2 + len ) then
          part = data
          break
        end

        msgs << data[ 2, len ]
        data = data[ ( 2 + len )..-1 ]
        break if data.empty?
      end

      [ msgs, part ]
    end

    def make_tunnel( ip, src )
      return if src.nil? || src.closed?
      src_info = @src_infos[ src ]
      domain = src_info[ :destination_domain ]
      port = src_info[ :destination_port ]

      if @local_ips.include?( ip ) && [ @redir_port, @tspd_port ].include?( port ) then
        puts "ignore #{ ip }:#{ port }"
        close_src( src )
        return
      end

      if [ domain, ip ].include?( @proxyd_host )  then
        # 访问远端，直连
        puts "direct #{ ip } #{ port }"
        new_a_dst( ip, src )
        return
      end

      if @is_direct_caches.include?( ip ) then
        is_direct = @is_direct_caches[ ip ]
      else
        begin
          is_direct = @directs.any?{ | direct | direct.include?( ip ) }
        rescue IPAddr::InvalidAddressError => e
          puts "make tunnel #{ e.class }"
          close_src( src )
          return
        end

        @is_direct_caches[ ip ] = is_direct
      end

      if is_direct then
        new_a_dst( ip, src )
      else
        set_remote( src )
      end
    end

    def new_a_dst( ip, src )
      return if src.nil? || src.closed?
      src_info = @src_infos[ src ]
      domain = src_info[ :destination_domain ]
      port = src_info[ :destination_port ]
      now = Time.new

      @dst_infos.select{ | dst, info | info[ :connected ] ? ( now.to_i - @updates[ dst ].to_i >= @expire_long_after ) : ( now.to_i - @updates[ dst ].to_i >= @expire_connecting ) }.each do | dst, info |
        puts "expire dst #{ info[ :domain ] }" if @is_debug
        close_dst( dst )
      end

      begin
        destination_addr = Socket.sockaddr_in( port, ip )
        dst = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      rescue Exception => e
        puts "new a dst #{ e.class } #{ domain } #{ ip }:#{ port }"
        close_src( src )
        return
      end

      dst.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )

      begin
        dst.connect_nonblock( destination_addr )
      rescue IO::WaitWritable
      rescue Exception => e
        puts "dst connect destination #{ e.class } #{ domain } #{ ip }:#{ port }"
        dst.close
        close_src( src )
        return
      end

      dst_info = {
        closing: false,
        connected: false,
        domain: domain,
        ip: ip,
        paused: false,
        port: port,
        src: src,
        wbuff: ''
      }

      @dst_infos[ dst ] = dst_info
      src_info[ :proxy_type ] = :direct
      src_info[ :dst ] = dst

      if src_info[ :proxy_proto ] == :http then
        if src_info[ :is_connect ] then
          puts "add HTTP_OK" if @is_debug
          add_src_wbuff( src, HTTP_OK )
        end
      elsif src_info[ :proxy_proto ] == :socks5 then
        puts "add_socks5_conn_reply" if @is_debug
        add_socks5_conn_reply( src )
      end

      add_read( dst, :dst )
      add_write( dst )
      data = src_info[ :rbuff ]

      unless data.empty? then
        puts "move src rbuff to dst #{ domain } #{ port } #{ data.bytesize }" if @is_debug
        add_dst_wbuff( dst, data )
      end
    end

    def new_a_memd( memd_port )
      memd_ip = '127.0.0.1'
      memd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      memd.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
      memd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 ) if RUBY_PLATFORM.include?( 'linux' )
      memd.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_FASTOPEN, 5 ) if @is_server_fastopen
      memd.bind( Socket.sockaddr_in( memd_port, memd_ip ) )
      memd.listen( 5 )
      puts "memd listen on #{ memd_ip } #{ memd_port }"
      add_read( memd, :memd )
    end

    def new_a_proxy
      proxy = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      proxy.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )

      if @is_client_fastopen then
        proxy.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_FASTOPEN, 5 )
      else
        begin
          proxy.connect_nonblock( @proxyd_addr )
        rescue IO::WaitWritable
        rescue Exception => e
          puts "connect proxyd #{ e.class }"
          proxy.close
          return
        end
      end

      proxy_info = {
        im: nil,
        in: 0,
        is_syn: @is_client_fastopen,
        out: 0,
        overflow_domains: {}, # src => destination_domain
        pause_domains: {}, # src => destination_domain
        rbuff: '',
        srcs: {}, # src_id => src
        wbuff: ''
      }

      add_read( proxy, :proxy )
      @proxy = proxy
      @proxy_infos[ proxy ] = proxy_info
      proxy_info
    end

    def new_a_redir( redir_port )
      redir_ip = '0.0.0.0'
      redir = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      redir.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 ) if RUBY_PLATFORM.include?( 'linux' )
      redir.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_FASTOPEN, BACKLOG ) if @is_server_fastopen
      redir.bind( Socket.sockaddr_in( redir_port, redir_ip ) )
      redir.listen( BACKLOG )
      puts "redir listen on #{ redir_ip } #{ redir_port }"
      add_read( redir, :redir )
      @redir_port = redir_port
      @redir_local_address = redir.local_address
    end

    def new_a_rsv( data, addrinfo, domain, type )
      now = Time.new

      @rsv_infos.select{ | rsv, _ | now.to_i - @updates[ rsv ].to_i >= @expire_short_after }.each do | rsv, info |
        puts "expire rsv #{ info[ :domain ] }" if @is_debug
        close_rsv( rsv )
      end

      rsv = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )

      begin
        @nameserver_addrs.each{ | addr | rsv.sendmsg( data, 0, addr ) }
      rescue Exception => e
        puts "rsv send data #{ e.class }"
        rsv.close
        return
      end

      rsv_info = {
        addrinfo: addrinfo,
        domain: domain,
        type: type
      }

      @rsv_infos[ rsv ] = rsv_info
      add_read( rsv, :rsv )
    end

    def new_a_rsvd( rsvd_port )
      rsvd_ip = '0.0.0.0'
      rsvd_addr = Socket.sockaddr_in( rsvd_port, rsvd_ip )
      rsvd = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      rsvd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 ) if RUBY_PLATFORM.include?( 'linux' )
      rsvd.bind( rsvd_addr )
      puts "rsvd bind on #{ rsvd_ip } #{ rsvd_port }"
      add_read( rsvd, :rsvd )
      @rsvd = rsvd
    end

    def new_a_tspd( tspd_port )
      tspd_ip = '0.0.0.0'
      tspd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      tspd.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
      tspd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      tspd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 ) if RUBY_PLATFORM.include?( 'linux' )
      tspd.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_FASTOPEN, BACKLOG ) if @is_server_fastopen
      tspd.bind( Socket.sockaddr_in( tspd_port, tspd_ip ) )
      tspd.listen( BACKLOG )
      puts "tspd listen on #{ tspd_ip } #{ tspd_port }"
      add_read( tspd, :tspd )
      @tspd_port = tspd_port
    end

    def pack_a_chunk( msg )
      "#{ [ msg.bytesize ].pack( 'n' ) }#{ msg }"
    end

    def pack_traffic( src_id, data )
      chunks = ''

      loop do
        part = data[ 0, 65526 ]
        # puts "add h_traffic #{ src_id } #{ part.bytesize }" if @is_debug
        msg = "#{ @h_traffic }#{ [ src_id ].pack( 'Q>' ) }#{ part }"
        chunks << pack_a_chunk( msg )
        data = data[ part.bytesize..-1 ]
        break if data.empty?
      end

      chunks
    end

    def read_dns( dns )
      begin
        data, addrinfo, rflags, *controls = dns.recvmsg
      rescue Exception => e
        puts "dns recvmsg #{ e.class }"
        close_dns( dns )
        return
      end

      return if data.empty?

      begin
        ip = seek_ip( data )
      rescue Exception => e
        puts "dns seek ip #{ e.class } #{ e.message }"
        close_dns( dns )
        return
      end

      dns_info = @dns_infos[ dns ]
      domain = dns_info[ :domain ]

      if ip then
        src = dns_info[ :src ]
        make_tunnel( ip, src )
        puts "set resolv cache #{ domain } #{ ip }" if @is_debug
        @resolv_caches[ domain ] = [ ip, Time.new ]
      else
        puts "no ip in answer #{ domain }"
        close_src( src )
      end

      close_dns( dns )
    end

    def read_dst( dst )
      begin
        data = dst.read_nonblock( READ_SIZE )
      rescue Errno::ENOTCONN => e
        return
      rescue Exception => e
        close_dst( dst )
        return
      end

      set_update( dst )
      dst_info = @dst_infos[ dst ]
      puts "read dst #{ dst_info[ :domain ] } #{ data.bytesize }" if @is_debug
      src = dst_info[ :src ]
      add_src_wbuff( src, data )
    end

    def read_mem( mem )
      begin
        mem.read_nonblock( READ_SIZE )
      rescue Errno::ENOTCONN => e
        return
      rescue Exception => e
        close_mem( mem )
        return
      end

      set_update( mem )
      src_arr = []

      @src_infos.each do | _, info |
        src_arr << {
          addrinfo: info[ :addrinfo ].ip_unpack,
          destination_domain: info[ :destination_domain ],
          destination_port: info[ :destination_port ]
        }
      end

      msg = {
        resolv_caches: @resolv_caches.sort,
        response_caches: @response_caches.sort.map{ | a | [ a[ 0 ], a[ 1 ][ 2 ], a[ 1 ][ 3 ] ] },
        response6_caches: @response6_caches.sort.map{ | a | [ a[ 0 ], a[ 1 ][ 2 ], a[ 1 ][ 3 ] ] },
        sizes: {
          directs: @directs.size,
          remotes: @remotes.size,
          reads: @reads.size,
          writes: @writes.size,
          roles: @roles.size,
          updates: @updates.size,
          proxy_infos: @proxy_infos.size,
          mem_infos: @mem_infos.size,
          src_infos: @src_infos.size,
          dst_infos: @dst_infos.size,
          dns_infos: @dns_infos.size,
          rsv_infos: @rsv_infos.size,
          near_infos: @near_infos.size,
          resolv_caches: @resolv_caches.size,
          is_direct_caches: @is_direct_caches.size,
          response_caches: @response_caches.size,
          response6_caches: @response6_caches.size
        },
        updates_limit: @updates_limit,
        eliminate_count: @eliminate_count,
        src_arr: src_arr
      }

      add_mem_wbuff( mem, JSON.generate( msg ) )
    end

    def read_memd( memd )
      now = Time.new

      @mem_infos.select{ | mem, _ | now.to_i - @updates[ mem ].to_i >= @expire_short_after }.each do | mem, _ |
        puts "expire mem" if @is_debug
        close_mem( mem )
      end

      begin
        mem, addrinfo = memd.accept_nonblock
      rescue Exception => e
        puts "memd accept #{ e.class }"
        return
      end

      mem_info = {
        wbuff: ''
      }

      @mem_infos[ mem ] = mem_info
      add_read( mem, :mem )
    end

    def read_proxy( proxy )
      begin
        data = proxy.read_nonblock( READ_SIZE )
      rescue Errno::ENOTCONN => e
        return
      rescue Exception => e
        close_proxy( proxy )
        return
      end

      set_update( proxy )
      proxy_info = @proxy_infos[ proxy ]
      data = "#{ proxy_info[ :rbuff ] }#{ data }"

      msgs, part = decode_to_msgs( data )
      msgs.each{ | msg | deal_msg( msg, proxy ) }
      proxy_info[ :rbuff ] = part
    end

    def read_redir( redir )
      now = Time.new

      @src_infos.select{ | src, _ | now.to_i - @updates[ src ].to_i >= @expire_long_after }.each do | src, info |
        puts "expire src #{ info[ :destination_domain ] }" if @is_debug
        close_src( src )
      end

      begin
        src, addrinfo = redir.accept_nonblock
      rescue IO::WaitReadable, Errno::EINTR => e
        puts "redir accept #{ e.class }"
        return
      end

      puts "redir accept a src #{ addrinfo.ip_unpack.inspect }" if @is_debug
      src_id = rand( ( 2 ** 64 ) - 2 ) + 1

      src_info = {
        addrinfo: addrinfo,
        closing: false,
        destination_domain: nil,
        destination_port: nil,
        dst: nil,
        is_connect: true,
        paused: false,
        proxy_proto: :uncheck, # :uncheck / :http / :socks5
        proxy_type: :uncheck,  # :uncheck / :checking / :negotiation / :remote / :direct
        rbuff: '',
        src_id: src_id,
        wbuff: ''
      }

      @src_infos[ src ] = src_info
      add_read( src, :src )
    end

    def read_rsv( rsv )
      begin
        data, addrinfo, rflags, *controls = rsv.recvmsg
      rescue Exception => e
        puts "rsv recvmsg #{ e.class }"
        close_rsv( rsv )
        return
      end

      return if data.empty?

      rsv_info = @rsv_infos[ rsv ]
      addrinfo = rsv_info[ :addrinfo ]
      domain = rsv_info[ :domain ]
      type = rsv_info[ :type ]
      send_data( @rsvd, data, addrinfo )

      begin
        ip = seek_ip( data )
      rescue Exception => e
        puts "rsv seek ip #{ e.class } #{ e.message }"
        close_rsv( rsv )
        return
      end

      if ip then
        if type == 1 then
          puts "set response cache #{ domain } #{ ip }" if @is_debug
          @response_caches[ domain ] = [ data, Time.new, ip, false ]
        else
          puts "set response6 cache #{ domain } #{ ip }" if @is_debug
          @response6_caches[ domain ] = [ data, Time.new, ip, false ]
        end
      end

      close_rsv( rsv )
    end

    def read_rsvd( rsvd )
      begin
        data, addrinfo, rflags, *controls = rsvd.recvmsg
      rescue Exception => e
        puts "rsvd recvmsg #{ e.class }"
        return
      end

      return if data.empty?

      begin
        id, domain, type = seek_question_dn( data )
      rescue Exception => e
        puts "seek question dn #{ e.class } #{ e.message }"
        return
      end

      return unless [ 1, 12, 28 ].include?( type )

      if type == 12 then
        new_a_rsv( data, addrinfo, domain, type )
        return
      end

      if type == 1 then
        response_cache = @response_caches[ domain ]
      else
        response_cache = @response6_caches[ domain ]
      end

      if response_cache then
        response, created_at = response_cache

        if Time.new - created_at < RESOLV_CACHE_EXPIRE then
          response[ 0, 2 ] = id
          send_data( @rsvd, response, addrinfo )
          return
        end

        if type == 1 then
          @response_caches.delete( domain )
        else
          @response6_caches.delete( domain )
        end
      end

      if @remotes.any?{ | r | domain.include?( r ) } then
        now = Time.new

        @near_infos.select{ | _, info | now.to_i - info[ :created_at ].to_i >= @expire_short_after }.each do | near_id, info |
          puts "expire near #{ info[ :domain ] }" if @is_debug
          @near_infos.delete( near_id )
        end

        near_id = rand( ( 2 ** 64 ) - 2 ) + 1

        near_info = {
          addrinfo: addrinfo,
          created_at: now,
          domain: domain,
          id: id,
          type: type
        }

        @near_infos[ near_id ] = near_info
        puts "add h_query #{ near_id } #{ type } #{ domain }" if @is_debug
        msg = "#{ @h_query }#{ [ near_id, type ].pack( 'Q>C' ) }#{ domain }"
        add_proxy_wbuff( pack_a_chunk( msg ) )
        return
      end

      new_a_rsv( data, addrinfo, domain, type )
    end

    def read_src( src )
      begin
        data = src.read_nonblock( READ_SIZE )
      rescue Errno::ENOTCONN => e
        return
      rescue Exception => e
        close_src( src )
        return
      end

      set_update( src )
      src_info = @src_infos[ src ]
      proxy_type = src_info[ :proxy_type ]

      case proxy_type
      when :uncheck then
        if data[ 0, 7 ] == 'CONNECT' then
          domain_port = data.split( "\r\n" )[ 0 ].split( ' ' )[ 1 ]

          unless domain_port then
            puts "CONNECT miss domain"
            close_src( src )
            return
          end
        elsif data[ 0 ].unpack( 'C' ).first == 5 then
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
            puts "miss method 00"
            close_src( src )
            return
          end

          # +----+--------+
          # |VER | METHOD |
          # +----+--------+
          # | 1  |   1    |
          # +----+--------+
          puts "read src version 5 nmethods #{ nmethods } methods #{ methods.inspect }" if @is_debug
          data2 = [ 5, 0 ].pack( 'CC' )
          add_src_wbuff( src, data2 )
          return if src.closed?
          src_info[ :proxy_proto ] = :socks5
          src_info[ :proxy_type ] = :negotiation
          return
        else
          host_line = data.split( "\r\n" ).find{ | _line | _line[ 0, 6 ] == 'Host: ' }

          unless host_line then
            close_src( src )
            return
          end

          lines = data.split( "\r\n" )

          unless lines.empty? then
            method, url, proto = lines.first.split( ' ' )

            if proto && url && proto[ 0, 4 ] == 'HTTP' && url[ 0, 7 ] == 'http://' then
              domain_port = url.split( '/' )[ 2 ]
            end
          end

          unless domain_port then
            domain_port = host_line.split( ' ' )[ 1 ]

            unless domain_port then
              puts "Host line miss domain"
              close_src( src )
              return
            end
          end

          src_info[ :is_connect ] = false
          add_src_rbuff( src, data )
        end

        colon_idx = domain_port.rindex( ':' )
        close_idx = domain_port.rindex( ']' )

        if colon_idx && ( close_idx.nil? || ( colon_idx > close_idx ) ) then
          domain = domain_port[ 0...colon_idx ]
          port = domain_port[ ( colon_idx + 1 )..-1 ].to_i
        else
          domain = domain_port
          port = 80
        end

        domain = domain.gsub( /\[|\]/, '' )
        src_info[ :proxy_proto ] = :http
        src_info[ :destination_domain ] = domain
        src_info[ :destination_port ] = port
        resolve_domain( domain, src )
      when :checking then
        add_src_rbuff( src, data )
      when :negotiation then
        # +----+-----+-------+------+----------+----------+
        # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        # +----+-----+-------+------+----------+----------+
        # | 1  |  1  | X'00' |  1   | Variable |    2     |
        # +----+-----+-------+------+----------+----------+
        ver, cmd, rsv, atyp = data[ 0, 4 ].unpack( 'C4' )

        if cmd == 1 then
          if atyp == 1 then
            destination_host, destination_port = data[ 4, 6 ].unpack( 'Nn' )

            begin
              destination_addr = Socket.sockaddr_in( destination_port, destination_host )
              destination_addrinfo = Addrinfo.new( destination_addr )
            rescue Exception => e
              puts "new addrinfo #{ e.class }"
              close_src( src )
              return
            end

            destination_ip = destination_addrinfo.ip_address
            puts "read src cmd #{ cmd } atyp #{ atyp } #{ destination_ip } #{ destination_port }" if @is_debug
            src_info[ :destination_domain ] = destination_ip
            src_info[ :destination_port ] = destination_port
            make_tunnel( destination_ip, src )
          elsif atyp == 3 then
            domain_len = data[ 4 ].unpack( 'C' ).first

            if ( domain_len + 7 ) == data.bytesize then
              domain = data[ 5, domain_len ]
              port = data[ ( 5 + domain_len ), 2 ].unpack( 'n' ).first
              puts "read src cmd #{ cmd } atyp #{ atyp } #{ domain } #{ port }" if @is_debug
              src_info[ :destination_domain ] = domain
              src_info[ :destination_port ] = port
              resolve_domain( domain, src )
            end
          else
            puts "socks5 atyp #{ atyp } not implement"
            close_src( src )
          end
        else
          puts "socks5 cmd #{ cmd } not implement"
          close_src( src )
        end
      when :remote then
        src_id = src_info[ :src_id ]
        add_proxy_wbuff( pack_traffic( src_id, data ) )
        proxy_info = @proxy_infos[ @proxy ]

        if proxy_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
          puts "pause src #{ src_info[ :destination_domain ] }"
          @reads.delete( src )
          proxy_info[ :pause_domains ][ src ] = src_info[ :destination_domain ]
        end
      when :direct then
        dst = src_info[ :dst ]

        if dst then
          add_dst_wbuff( dst, data )
        else
          add_src_rbuff( src, data )
        end
      end
    end

    def read_tspd( tspd )
      now = Time.new

      @src_infos.select{ | src, _ | now.to_i - @updates[ src ].to_i >= @expire_long_after }.each do | src, info |
        puts "expire src #{ info[ :destination_domain ] }" if @is_debug
        close_src( src )
      end

      begin
        src, addrinfo = tspd.accept_nonblock
      rescue IO::WaitReadable, Errno::EINTR => e
        puts "tspd accept #{ e.class }"
        return
      end

      puts "tspd accept a src #{ addrinfo.ip_unpack.inspect }" if @is_debug

      begin
        # /usr/include/linux/netfilter_ipv4.h
        option = src.getsockopt( Socket::SOL_IP, 80 )
      rescue Exception => e
        puts "get SO_ORIGINAL_DST #{ e.class } #{ addrinfo.ip_unpack.inspect }"
        src.close
        return
      end

      dest_family, dest_port, dest_host = option.unpack( 'nnN' )
      dest_addr = Socket.sockaddr_in( dest_port, dest_host )
      dest_addrinfo = Addrinfo.new( dest_addr )
      dest_ip = dest_addrinfo.ip_address
      src_id = rand( ( 2 ** 64 ) - 2 ) + 1

      src_info = {
        addrinfo: addrinfo,
        closing: false,
        destination_domain: dest_ip,
        destination_port: dest_port,
        dst: nil,
        is_connect: true,
        paused: false,
        proxy_proto: :uncheck, # :uncheck / :http / :socks5
        proxy_type: :uncheck,  # :uncheck / :checking / :negotiation / :remote / :direct
        rbuff: '',
        src_id: src_id,
        wbuff: ''
      }

      @src_infos[ src ] = src_info
      add_read( src, :src )
      make_tunnel( dest_ip, src )
    end

    def resolve_domain( domain, src )
      return if src.nil? || src.closed?

      unless domain =~ /^[0-9a-zA-Z\-\.]{1,63}$/ then
        # 忽略非法域名
        puts "ignore #{ domain }"
        close_src( src )
        return
      end

      if domain == 'localhost' then
        domain = "127.0.0.1"
      end

      if domain =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}$/ then
        # ipv4
        make_tunnel( domain, src )
        return
      end

      if @remotes.any?{ | remote | ( domain.size >= remote.size ) && ( domain[ ( remote.size * -1 )..-1 ] == remote ) } then
        set_remote( src )
        return
      end

      resolv_cache = @resolv_caches[ domain ]

      if resolv_cache then
        ip, created_at = resolv_cache

        if Time.new - created_at < RESOLV_CACHE_EXPIRE then
          make_tunnel( ip, src )
          return
        end

        @resolv_caches.delete( domain )
      end

      begin
        data = pack_a_query( domain )
      rescue Exception => e
        puts "pack a query #{ e.class } #{ e.message } #{ domain }"
        close_src( src )
        return
      end

      now = Time.new

      @dns_infos.select{ | dns, _ | now.to_i - @updates[ dns ].to_i >= @expire_short_after }.each do | dns, info |
        puts "expire dns #{ info[ :domain ] }" if @is_debug
        close_dns( dns )
      end

      dns = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )

      begin
        @nameserver_addrs.each{ | addr | dns.sendmsg( data, 0, addr ) }
      rescue Exception => e
        puts "dns send data #{ e.class }"
        dns.close
        close_src( src )
        return
      end

      dns_info = {
        domain: domain,
        src: src
      }

      @dns_infos[ dns ] = dns_info
      add_read( dns, :dns )
      src_info = @src_infos[ src ]
      src_info[ :proxy_type ] = :checking
    end

    def send_data( sock, data, target_addr )
      begin
        sock.sendmsg( data, 0, target_addr )
      rescue Exception => e
        puts "sendmsg #{ e.class }"
      end
    end

    def set_dst_closing( dst )
      return if dst.nil? || dst.closed?
      dst_info = @dst_infos[ dst ]
      return if dst_info.nil? || dst_info[ :closing ]
      dst_info[ :closing ] = true
      add_write( dst )
    end

    def set_remote( src )
      return if src.nil? || src.closed?
      src_info = @src_infos[ src ]
      src_info[ :proxy_type ] = :remote

      if src_info[ :proxy_proto ] == :http then
        if src_info[ :is_connect ] then
          puts "add HTTP_OK #{ src_info[ :proxy_type ] }" if @is_debug
          add_src_wbuff( src, HTTP_OK )
        end
      elsif src_info[ :proxy_proto ] == :socks5 then
        puts "add_socks5_conn_reply #{ src_info[ :proxy_type ] }" if @is_debug
        add_socks5_conn_reply( src )
      end

      src_id = src_info[ :src_id ]
      destination_domain = src_info[ :destination_domain ]
      destination_port = src_info[ :destination_port ]
      domain_port = [ destination_domain, destination_port ].join( ':' )
      puts "add h_a_new_source #{ src_id } #{ domain_port }" if @is_debug
      msg = "#{ @h_a_new_source }#{ [ src_id ].pack( 'Q>' ) }#{ domain_port }"
      add_proxy_wbuff( pack_a_chunk( msg ) )
      proxy_info = @proxy_infos[ @proxy ]
      proxy_info[ :srcs ][ src_id ] = src
      data = src_info[ :rbuff ]

      unless data.empty? then
        puts "move src rbuff to proxy #{ destination_domain } #{ destination_port } #{ data.bytesize }" if @is_debug
        add_proxy_wbuff( pack_traffic( src_id, data ) )
      end
    end

    def set_src_closing( src )
      return if src.nil? || src.closed?
      src_info = @src_infos[ src ]
      return if src_info.nil? || src_info[ :closing ]
      src_info[ :closing ] = true
      add_write( src )
    end

    def set_update( sock )
      @updates[ sock ] = Time.new

      if @updates_limit - @updates.size <= 20 then
        puts "updates #{ @updates.size }"
      end

      if @updates.size >= @updates_limit then
        puts "eliminate updates"

        @updates.keys.each do | _sock |
          case @roles[ _sock ]
          when :dns
            close_dns( _sock )
          when :dst
            close_dst( _sock )
          when :mem
            close_mem( _sock )
          when :src
            close_src( _sock )
          when :rsv
            close_rsv( _sock )
          else
            close_sock( _sock )
          end
        end

        @eliminate_count += 1
      end
    end

    def write_dst( dst )
      if dst.closed? then
        puts "write closed dst?"
        return
      end

      dst_info = @dst_infos[ dst ]
      dst_info[ :connected ] = true
      data = dst_info[ :wbuff ]

      if data.empty? then
        if dst_info[ :closing ] then
          close_dst( dst )
        else
          @writes.delete( dst )
        end

        return
      end

      begin
        written = dst.write_nonblock( data )
      rescue Errno::EINPROGRESS
        return
      rescue Exception => e
        close_dst( dst )
        return
      end

      set_update( dst )
      data = data[ written..-1 ]
      dst_info[ :wbuff ] = data
      src = dst_info[ :src ]

      if src && !src.closed? then
        src_info = @src_infos[ src ]

        if src_info[ :paused ] && ( dst_info[ :wbuff ].bytesize < RESUME_BELOW ) then
          puts "resume direct src #{ src_info[ :destination_domain ] }"
          add_read( src )
          src_info[ :paused ] = false unless src.closed?
        end
      end
    end

    def write_mem( mem )
      if mem.closed? then
        puts "write closed mem?"
        return
      end

      mem_info = @mem_infos[ mem ]
      data = mem_info[ :wbuff ]

      if data.empty? then
        @writes.delete( mem )
        close_mem( mem )
        return
      end

      begin
        written = mem.write_nonblock( data )
      rescue Errno::EINPROGRESS
        return
      rescue Exception => e
        close_mem( mem )
        return
      end

      set_update( mem )
      data = data[ written..-1 ]
      mem_info[ :wbuff ] = data
    end

    def write_src( src )
      if src.closed? then
        puts "write closed src?"
        return
      end

      src_info = @src_infos[ src ]
      data = src_info[ :wbuff ]

      if data.empty? then
        if src_info[ :closing ] then
          close_src( src )
        else
          @writes.delete( src )
        end

        return
      end

      begin
        written = src.write_nonblock( data )
      rescue Errno::EINPROGRESS
        return
      rescue Exception => e
        close_src( src )
        return
      end

      set_update( src )
      data = data[ written..-1 ]
      src_info[ :wbuff ] = data
      dst = src_info[ :dst ]

      if dst then
        unless dst.closed? then
          dst_info = @dst_infos[ dst ]

          if dst_info[ :paused ] && ( src_info[ :wbuff ].bytesize < RESUME_BELOW ) then
            puts "resume dst #{ dst_info[ :domain ] }"
            add_read( dst )
            dst_info[ :paused ] = false unless dst.closed?
          end
        end
      elsif @proxy && !@proxy.closed? then
        proxy_info = @proxy_infos[ @proxy ]
        domain = proxy_info[ :overflow_domains ][ src ]

        if domain && ( src_info[ :wbuff ].bytesize < RESUME_BELOW ) then
          puts "delete overflow #{ domain }"
          proxy_info[ :overflow_domains ].delete( src )

          if proxy_info[ :overflow_domains ].empty? then
            puts "resume proxy"
            add_read( @proxy )
          end
        end
      end
    end

    def write_proxy( proxy )
      if proxy.closed? then
        puts "write closed proxy?"
        return
      end

      proxy_info = @proxy_infos[ proxy ]
      data = proxy_info[ :wbuff ]

      if data.empty? then
        @writes.delete( proxy )
        return
      end

      begin
        if proxy_info[ :is_syn ] then
          written = proxy.sendmsg_nonblock( data, 536870912, @proxyd_addr )
          proxy_info[ :is_syn ] = false
        else
          written = proxy.write_nonblock( data )
        end
      rescue Errno::EINPROGRESS
        return
      rescue Exception => e
        close_proxy( proxy )
        return
      end

      set_update( proxy )
      data = data[ written..-1 ]
      proxy_info[ :wbuff ] = data

      if proxy_info[ :pause_domains ].any? && ( proxy_info[ :wbuff ].bytesize < RESUME_BELOW ) then
        proxy_info[ :pause_domains ].each do | src, domain |
          puts "resume src #{ domain }"
          add_read( src )
        end

        proxy_info[ :pause_domains ].clear
      end
    end

  end
end
