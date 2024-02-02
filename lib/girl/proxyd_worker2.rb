module Girl
  class ProxydWorker2
    include Dns

    def initialize(
      proxyd_port,
      memd_port,
      nameservers,
      reset_traff_day,
      ims,
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
      is_server_fastopen )

      @nameserver_addrs = nameservers.map{ | n | Socket.sockaddr_in( 53, n ) }
      @reset_traff_day = reset_traff_day
      @ims = ims
      @update_roles = [ :dns, :dst, :mem, :proxy, :rsv ] # 参与淘汰的角色
      @updates_limit = 1011 # 淘汰池上限，1015(mac) - [ info, infod, memd, proxyd ]
      @reads = []           # 读池
      @writes = []          # 写池
      @updates = {}         # sock => updated_at
      @eliminate_count = 0  # 淘汰次数
      @roles = {}           # sock => :dns / :dst / :info / :infod / :mem / :memd / :proxy / :proxyd / :rsv
      @mem_infos = {}       # mem => { :wbuff }
      @resolv_caches = {}   # domain => [ ip, created_at, im ]
      @dst_infos = {}       # dst => { :closing :connected :domain :im :ip :proxy :rbuffs :src_id :wbuff }
      @dns_infos = {}       # dns => { :domain :im :port :proxy :src_id }
      @rsv_infos = {}       # rsv => { :domain :im :near_id :proxy  }
      @proxy_infos = {}     # proxy => { :addrinfo :dsts :im :in :out :overflow_domains :pause_domains :rbuff :wbuff }
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
      @is_server_fastopen = is_server_fastopen

      new_a_proxyd( proxyd_port )
      new_a_infod( proxyd_port )
      new_a_memd( memd_port )
    end

    def looping
      puts "looping"
      loop_check_traff

      loop do
        rs, ws = IO.select( @reads, @writes )

        rs.each do | sock |
          role = @roles[ sock ]

          case role
          when :dns then
            read_dns( sock )
          when :dst then
            read_dst( sock )
          when :infod then
            read_infod( sock )
          when :mem then
            read_mem( sock )
          when :memd then
            read_memd( sock )
          when :rsv then
            read_rsv( sock )
          when :proxy then
            read_proxy( sock )
          when :proxyd then
            read_proxyd( sock )
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
      return if dst.nil? || dst.closed? || data.nil? || data.empty?
      dst_info = @dst_infos[ dst ]
      dst_info[ :wbuff ] << data
      add_write( dst )

      if !dst.closed? && dst_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        proxy = dst_info[ :proxy ]

        if proxy.closed? then
          close_dst( dst )
          return
        end

        proxy_info = @proxy_infos[ proxy ]
        puts "overflow #{ proxy_info[ :im ] } #{ dst_info[ :domain ] }"
        @reads.delete( proxy )
        proxy_info[ :overflow_domains ][ dst ] = dst_info[ :domain ]
      end
    end

    def add_mem_wbuff( mem, data )
      return if mem.nil? || mem.closed? || data.nil? || data.empty?
      mem_info = @mem_infos[ mem ]
      mem_info[ :wbuff ] << data
      add_write( mem )
    end

    def add_proxy_wbuff( proxy, data )
      return if proxy.nil? || proxy.closed? || data.nil? || data.empty?
      proxy_info = @proxy_infos[ proxy ]
      proxy_info[ :wbuff ] << data
      add_write( proxy )
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
      dns_info
    end

    def close_dst( dst )
      return nil if dst.nil? || dst.closed?
      close_sock( dst )
      dst_info = @dst_infos.delete( dst )
      proxy = dst_info[ :proxy ]

      unless proxy.closed? then
        proxy_info = @proxy_infos[ proxy ]
        src_id = dst_info[ :src_id ]

        if proxy_info[ :dsts ].delete( src_id ) then
          puts "add h_dst_close #{ src_id }" if @is_debug
          msg = "#{ @h_dst_close }#{ [ src_id ].pack( 'Q>' ) }"
          add_proxy_wbuff( proxy, pack_a_chunk( msg ) )
        end
      end

      dst_info
    end

    def close_mem( mem )
      return nil if mem.nil? || mem.closed?
      close_sock( mem )
      @mem_infos.delete( mem )
    end

    def close_proxy( proxy )
      return nil if proxy.nil? || proxy.closed?
      close_sock( proxy )
      proxy_info = @proxy_infos.delete( proxy )
      proxy_info[ :dsts ].values.each{ | dst | set_dst_closing( dst ) }
      proxy_info
    end

    def close_rsv( rsv )
      return nil if rsv.nil? || rsv.closed?
      close_sock( rsv )
      rsv_info = @rsv_infos.delete( rsv )
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

    def deal_msg( data, proxy )
      return if data.nil? || data.empty? || proxy.nil? || proxy.closed?
      proxy_info = @proxy_infos[ proxy ]
      return unless proxy_info[ :im ]
      h = data[ 0 ]

      case h
      when @h_a_new_source then
        return if data.bytesize < 9
        src_id = data[ 1, 8 ].unpack( 'Q>' ).first
        domain_port = data[ 9..-1 ]
        puts "got h_a_new_source #{ src_id } #{ domain_port.inspect }" if @is_debug
        resolve_domain_port( domain_port, src_id, proxy, proxy_info[ :im ] )
      when @h_query then
        return if data.bytesize < 10
        near_id, type = data[ 1, 9 ].unpack( 'Q>C' )
        return unless [ 1, 28 ].include?( type )
        domain = data[ 10..-1 ]
        return if domain.nil? || domain.empty?
        puts "got h_query #{ near_id } #{ type } #{ domain.inspect }" if @is_debug
        new_a_rsv( domain, near_id, type, proxy, proxy_info[ :im ] )
      when @h_traffic then
        return if data.bytesize < 3
        src_id = data[ 1, 8 ].unpack( 'Q>' ).first
        data = data[ 9..-1 ]
        puts "got h_traffic #{ src_id } #{ data.bytesize }" if @is_debug
        dst = proxy_info[ :dsts ][ src_id ]
        add_dst_wbuff( dst, data )
      when @h_src_close then
        return if data.bytesize < 9
        src_id = data[ 1, 8 ].unpack( 'Q>' ).first
        puts "got h_src_close #{ src_id }" if @is_debug
        dst = proxy_info[ :dsts ].delete( src_id )
        set_dst_closing( dst )
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

    def loop_check_traff
      if @reset_traff_day > 0 then
        Thread.new do
          loop do
            sleep CHECK_TRAFF_INTERVAL

            if Time.new.day == @reset_traff_day then
              msg = { message_type: 'reset-traffic' }
              send_data( @info, JSON.generate( msg ), @infod_addr )
            end
          end
        end
      end
    end

    def new_a_dst( domain, ip, port, src_id, proxy )
      return if proxy.nil? || proxy.closed?
      proxy_info = @proxy_infos[ proxy ]
      im = proxy_info[ :im ]
      now = Time.new

      @dst_infos.select{ | dst, info | info[ :connected ] ? ( now.to_i - @updates[ dst ].to_i >= @expire_long_after ) : ( now.to_i - @updates[ dst ].to_i >= @expire_connecting ) }.each do | dst, info |
        puts "expire dst #{ info[ :domain ] }" if @is_debug
        close_dst( dst )
      end

      begin
        dst = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      rescue Exception => e
        puts "new a dst #{ e.class } #{ im } #{ domain }:#{ port }"
        return
      end

      dst.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )

      begin
        destination_addr = Socket.sockaddr_in( port, ip )
        dst.connect_nonblock( destination_addr )
      rescue IO::WaitWritable
      rescue Exception => e
        puts "connect destination #{ e.class } #{ im } #{ domain }:#{ port }"
        dst.close
        return
      end

      dst_info = {
        closing: false,
        connected: false,
        domain: domain,
        im: im,
        ip: ip,
        proxy: proxy,
        rbuffs: [],
        src_id: src_id,
        wbuff: ''
      }

      @dst_infos[ dst ] = dst_info
      add_read( dst, :dst )
      add_write( dst )
      proxy_info[ :dsts ][ src_id ] = dst
    end

    def new_a_infod( infod_port )
      infod_addr = Socket.sockaddr_in( infod_port, '127.0.0.1' )
      infod = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      infod.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 ) if RUBY_PLATFORM.include?( 'linux' )
      infod.bind( infod_addr )
      puts "infod bind on #{ infod_port }"
      add_read( infod, :infod )
      info = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      @infod_addr = infod_addr
      @infod = infod
      @info = info
    end

    def new_a_memd( memd_port )
      memd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      memd.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
      memd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 ) if RUBY_PLATFORM.include?( 'linux' )
      memd.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_FASTOPEN, 5 ) if @is_server_fastopen
      memd.bind( Socket.sockaddr_in( memd_port, '127.0.0.1' ) )
      memd.listen( 5 )
      puts "memd listen on #{ memd_port }"
      add_read( memd, :memd )
    end

    def new_a_rsv( domain, near_id, type, proxy, im )
      now = Time.new

      @rsv_infos.select{ | rsv, _ | now.to_i - @updates[ rsv ].to_i >= @expire_short_after }.each do | rsv, info |
        puts "expire rsv #{ info[ :domain ] }" if @is_debug
        close_rsv( rsv )
      end

      rsv = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )

      begin
        data = pack_a_query( domain, type )
      rescue Exception => e
        puts "rsv pack a query #{ e.class } #{ e.message } #{ domain }"
        return
      end

      begin
        @nameserver_addrs.each{ | addr | rsv.sendmsg( data, 0, addr ) }
      rescue Exception => e
        puts "rsv send data #{ e.class }"
        rsv.close
        return
      end

      rsv_info = {
        domain: domain,
        im: im,
        near_id: near_id,
        proxy: proxy
      }

      @rsv_infos[ rsv ] = rsv_info
      add_read( rsv, :rsv )
    end

    def new_a_proxyd( proxyd_port )
      proxyd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      proxyd.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
      proxyd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 ) if RUBY_PLATFORM.include?( 'linux' )
      proxyd.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_FASTOPEN, BACKLOG ) if @is_server_fastopen
      proxyd.bind( Socket.sockaddr_in( proxyd_port, '0.0.0.0' ) )
      proxyd.listen( BACKLOG )
      puts "proxyd listen on #{ proxyd_port }"
      add_read( proxyd, :proxyd )
    end

    def pack_a_chunk( msg )
      "#{ [ msg.bytesize ].pack( 'n' ) }#{ msg }"
    end

    def pack_traffic( src_id, data )
      chunks = ''

      loop do
        part = data[ 0, 65526 ]
        puts "add h_traffic #{ src_id } #{ part.bytesize }" if @is_debug
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
        puts "seek ip #{ e.class } #{ e.message }"
        close_dns( dns )
        return
      end

      dns_info = @dns_infos[ dns ]
      domain = dns_info[ :domain ]

      if ip then
        port = dns_info[ :port ]
        src_id = dns_info[ :src_id ]
        proxy = dns_info[ :proxy ]
        im = dns_info[ :im ]
        puts "got ip #{ im } #{ domain } #{ ip }" if @is_debug
        new_a_dst( domain, ip, port, src_id, proxy )
        @resolv_caches[ domain ] = [ ip, Time.new, im ]
      else
        puts "no ip in answer #{ domain }"
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
      proxy = dst_info[ :proxy ]

      if proxy.closed? then
        close_dst( dst )
        return
      end

      proxy_info = @proxy_infos[ proxy ]
      proxy_info[ :in ] += data.bytesize
      src_id = dst_info[ :src_id ]
      puts "add pack_traffic #{ src_id } #{ data.bytesize }" if @is_debug
      add_proxy_wbuff( proxy, pack_traffic( src_id, data ) )

      if proxy_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        puts "pause dst #{ dst_info[ :im ] } #{ dst_info[ :domain ] }"
        @reads.delete( dst )
        proxy_info[ :pause_domains ][ dst ] = dst_info[ :domain ]
      end
    end

    def read_infod( infod )
      begin
        data, addrinfo, rflags, *controls = infod.recvmsg
      rescue Exception => e
        puts "infod recvmsg #{ e.class }"
        return
      end

      return if data.empty?

      begin
        msg = JSON.parse( data, symbolize_names: true )
      rescue JSON::ParserError, EncodingError => e
        puts "read infod #{ e.class }"
        return
      end

      message_type = msg[ :message_type ]

      case message_type
      when 'reset-traffic' then
        puts "reset traffic"
        @proxy_infos.each{ | _, info | info[ :in ] = info[ :out ] = 0 }
      end
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
      proxy_arr = []

      @proxy_infos.each do | _, info |
        proxy_arr << {
          addrinfo: info[ :addrinfo ].ip_unpack,
          im: info[ :im ],
          in: info[ :in ],
          out: info[ :out ]
        }
      end

      msg = {
        resolv_caches: @resolv_caches.sort,
        sizes: {
          reads: @reads.size,
          writes: @writes.size,
          updates: @updates.size,
          proxy_infos: @proxy_infos.size,
          mem_infos: @mem_infos.size,
          dst_infos: @dst_infos.size,
          dns_infos: @dns_infos.size,
          rsv_infos: @rsv_infos.size,
          resolv_caches: @resolv_caches.size
        },
        updates_limit: @updates_limit,
        eliminate_count: @eliminate_count,
        proxy_arr: proxy_arr
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

    def read_rsv( rsv )
      begin
        data, addrinfo, rflags, *controls = rsv.recvmsg
      rescue Exception => e
        puts "rsv recvmsg #{ e.class }"
        close_rsv( rsv )
        return
      end

      return if data.empty?

      if data.bytesize <= 65532 then
        rsv_info = @rsv_infos[ rsv ]
        proxy = rsv_info[ :proxy ]
        near_id = rsv_info[ :near_id ]
        puts "add h_response #{ near_id } #{ rsv_info[ :domain ] } #{ data.bytesize }" if @is_debug
        msg = "#{ @h_response }#{ [ near_id ].pack( 'Q>' ) }#{ data }"
        add_proxy_wbuff( proxy, pack_a_chunk( msg ) )
      else
        puts "response too big? #{ data.bytesize }"
      end

      close_rsv( rsv )
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
      proxy_info[ :in ] += data.bytesize
      data = "#{ proxy_info[ :rbuff ] }#{ data }"

      unless proxy_info[ :im ] then
        if data.bytesize < @head_len + 1 then
          proxy_info[ :rbuff ] = data
          return
        end

        len = data[ @head_len ].unpack( 'C' ).first

        if len == 0 then
          puts "im zero len?"
          return
        end

        if data.bytesize < @head_len + 1 + len then
          proxy_info[ :rbuff ] = data
          return
        end

        im = data[ @head_len + 1, len ]

        unless @ims.include?( im ) then
          puts "unknown im #{ im.inspect }"
          return
        end

        puts "im #{ im }" if @is_debug
        proxy_info[ :im ] = im
        data = data[ ( @head_len + 1 + len )..-1 ]
        return if data.empty?
      end

      msgs, part = decode_to_msgs( data )
      msgs.each{ | msg | deal_msg( msg, proxy ) }
      proxy_info[ :rbuff ] = part
    end

    def read_proxyd( proxyd )
      now = Time.new

      @proxy_infos.select{ | proxy, _ | now.to_i - @updates[ proxy ].to_i >= @expire_long_after }.each do | proxy, info |
        puts "expire proxy #{ info[ :im ] }" if @is_debug
        close_proxy( proxy )
      end

      begin
        proxy, addrinfo = proxyd.accept_nonblock
      rescue Exception => e
        puts "accept a proxy #{ e.class }"
        return
      end

      puts "accept a proxy #{ addrinfo.ip_unpack.inspect }"

      proxy_info = {
        addrinfo: addrinfo,
        dsts: {}, # src_id => dst
        im: nil,
        in: 0,
        out: 0,
        overflow_domains: {}, # dst => domain
        pause_domains: {}, # dst => domain
        rbuff: '',
        wbuff: ''
      }

      @proxy_infos[ proxy ] = proxy_info
      add_read( proxy, :proxy )
    end

    def resolve_domain_port( domain_port, src_id, proxy, im )
      return if domain_port.nil? || domain_port.empty?
      colon_idx = domain_port.rindex( ':' )
      return unless colon_idx

      domain = domain_port[ 0...colon_idx ]
      port = domain_port[ ( colon_idx + 1 )..-1 ].to_i

      if ( domain !~ /^[0-9a-zA-Z\-\.]{1,63}$/ ) || ( domain =~ /^((0\.\d{1,3}\.\d{1,3}\.\d{1,3})|(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(127\.\d{1,3}\.\d{1,3}\.\d{1,3})|(169\.254\.\d{1,3}\.\d{1,3})|(172\.((1[6-9])|(2\d)|(3[01]))\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3})|(255\.255\.255\.255)|(localhost))$/ ) then
        # 忽略非法域名，内网地址
        puts "ignore #{ domain }"
        return
      end

      if domain =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}$/ then
        # ipv4
        new_a_dst( domain, domain, port, src_id, proxy )
        return
      end

      resolv_cache = @resolv_caches[ domain ]

      if resolv_cache then
        ip, created_at, im = resolv_cache

        if Time.new - created_at < RESOLV_CACHE_EXPIRE then
          new_a_dst( domain, ip, port, src_id, proxy )
          return
        end

        @resolv_caches.delete( domain )
      end

      begin
        data = pack_a_query( domain )
      rescue Exception => e
        puts "dns pack a query #{ e.class } #{ e.message } #{ domain }"
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
        puts "dns send data #{ e.class } #{ domain }"
        dns.close
        return
      end

      dns_info = {
        domain: domain,
        im: im,
        port: port,
        proxy: proxy,
        src_id: src_id
      }

      @dns_infos[ dns ] = dns_info
      add_read( dns, :dns )
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
          when :proxy
            close_proxy( _sock )
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
      proxy = dst_info[ :proxy ]

      if proxy.closed? then
        close_dst( dst )
        return
      end

      proxy_info = @proxy_infos[ proxy ]
      proxy_info[ :out ] += written

      domain = proxy_info[ :overflow_domains ][ dst ]

      if domain && ( dst_info[ :wbuff ].bytesize < RESUME_BELOW ) then
        puts "delete overflow #{ domain }"
        proxy_info[ :overflow_domains ].delete( dst )

        if proxy_info[ :overflow_domains ].empty? then
          puts "resume proxy #{ proxy_info[ :im ] }"
          add_read( proxy )
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
        written = proxy.write_nonblock( data )
      rescue Errno::EINPROGRESS
        return
      rescue Exception => e
        close_proxy( proxy )
        return
      end

      set_update( proxy )
      data = data[ written..-1 ]
      proxy_info[ :wbuff ] = data
      proxy_info[ :out ] += written

      if proxy_info[ :pause_domains ].any? && ( proxy_info[ :wbuff ].bytesize < RESUME_BELOW ) then
        proxy_info[ :pause_domains ].each do | dst, domain |
          puts "resume dst #{ proxy_info[ :im ] } #{ domain }"
          add_read( dst )
        end

        proxy_info[ :pause_domains ].clear
      end
    end

  end
end
