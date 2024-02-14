module Girl
  class ProxydWorker
    include Dns

    def initialize(
      proxyd_port,
      memd_port,
      nameservers,
      reset_traff_day,
      ims,
      p2d_host,
      p2d_port,
      head_len,
      h_a_new_source,
      h_a_new_p2,
      h_dst_close,
      h_heartbeat,
      h_p1_close,
      h_p2_close,
      h_p2_traffic,
      h_query,
      h_response,
      h_src_close,
      h_traffic,
      h_p1_overflow,
      h_p1_underhalf,
      h_src_overflow,
      h_src_underhalf,
      expire_connecting,
      expire_long_after,
      expire_proxy_after,
      expire_resolv_cache,
      expire_short_after,
      is_debug,
      is_server_fastopen )

      @nameserver_addrs = nameservers.map{ | n | Socket.sockaddr_in( 53, n ) }
      @reset_traff_day = reset_traff_day
      @update_roles = [ :dns, :dst, :mem, :p2, :proxy, :rsv ] # 参与淘汰的角色
      @updates_limit = 1011 - ims.size # 淘汰池上限，1015(mac) - info, infod, memd, proxyd, p2ds(=ims)
      @eliminate_count = 0 # 淘汰次数
      @reads = []          # 读池
      @writes = []         # 写池
      @roles = {}          # sock => :dns / :dst / :infod / :mem / :memd / :p2 / :p2d / :proxy / :proxyd / :rsv
      @updates = {}        # sock => updated_at
      @proxy_infos = {}    # proxy => { :addrinfo :im :overflow_infos :p2s :pause_domains :pause_p2_ids :rbuff :src_infos :wbuff }
      @im_infos = {}       # im => { :addrinfo :in :out :p2d :p2d_host :p2d_port :proxy }
      @mem_infos = {}      # mem => { :wbuff }
      @dst_infos = {}      # dst => { :closing :connected :domain :im :ip :paused :port :proxy :rbuffs :src_id :wbuff }
      @dns_infos = {}      # dns => { :domain :im :port :proxy :src_id }
      @rsv_infos = {}      # rsv => { :domain :im :near_id :proxy  }
      @resolv_caches = {}  # domain => [ ip, created_at, im ]
      @p2d_infos = {}      # p2d => { :im }
      @p2_infos = {}       # p2 => { :addrinfo :im :p2_id :paused :proxy :wbuff }

      @head_len = head_len
      @h_a_new_source = h_a_new_source
      @h_a_new_p2 = h_a_new_p2
      @h_dst_close = h_dst_close
      @h_heartbeat = h_heartbeat
      @h_p1_close = h_p1_close
      @h_p2_close = h_p2_close
      @h_p2_traffic = h_p2_traffic
      @h_query = h_query
      @h_response = h_response
      @h_src_close = h_src_close
      @h_traffic = h_traffic
      @h_p1_overflow = h_p1_overflow
      @h_p1_underhalf = h_p1_underhalf
      @h_src_overflow = h_src_overflow
      @h_src_underhalf = h_src_underhalf
      @expire_connecting = expire_connecting
      @expire_long_after = expire_long_after
      @expire_proxy_after = expire_proxy_after
      @expire_resolv_cache = expire_resolv_cache
      @expire_short_after = expire_short_after
      @is_debug = is_debug
      @is_server_fastopen = is_server_fastopen

      init_im_infos( ims, p2d_host, p2d_port )
      new_a_proxyd( proxyd_port )
      new_a_infod( proxyd_port )
      new_a_memd( memd_port )
    end

    def looping
      puts "looping"
      loop_heartbeat
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
          when :p2 then
            read_p2( sock )
          when :p2d then
            read_p2d( sock )
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
          when :p2 then
            write_p2( sock )
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

      if !dst.closed? && ( dst_info[ :wbuff ].bytesize >= WBUFF_LIMIT ) then
        proxy = dst_info[ :proxy ]

        if proxy.closed? then
          close_dst( dst )
          return
        end

        proxy_info = @proxy_infos[ proxy ]
        puts "overflow dst #{ proxy_info[ :im ] } #{ dst_info[ :domain ] }"
        @reads.delete( proxy )

        proxy_info[ :overflow_infos ][ dst ] = {
          created_at: Time.new,
          domain: dst_info[ :domain ],
          p2_id: nil,
          role: :dst
        }
      end
    end

    def add_mem_wbuff( mem, data )
      return if mem.nil? || mem.closed? || data.nil? || data.empty?
      mem_info = @mem_infos[ mem ]
      mem_info[ :wbuff ] << data
      add_write( mem )
    end

    def add_p2_wbuff( p2, data )
      return if p2.nil? || p2.closed? || data.nil? || data.empty?
      p2_info = @p2_infos[ p2 ]
      p2_info[ :wbuff ] << data
      add_write( p2 )

      if !p2.closed? && ( p2_info[ :wbuff ].bytesize >= WBUFF_LIMIT ) then
        im = p2_info[ :im ]
        im_info = @im_infos[ im ]

        unless im_info then
          close_p2( p2 )
          return
        end

        proxy = im_info[ :proxy ]

        if proxy.closed? then
          close_p2( p2 )
          return
        end

        p2_id = p2_info[ :p2_id ]
        puts "overflow p2 #{ im } #{ p2_id }"
        @reads.delete( proxy )
        proxy_info = @proxy_infos[ proxy ]

        proxy_info[ :overflow_infos ][ p2 ] = {
          created_at: Time.new,
          domain: nil,
          p2_id: p2_id,
          role: :p2
        }
      end
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

    def check_expire_dnses
      now = Time.new

      @dns_infos.select{ | dns, _ | now.to_i - @updates[ dns ].to_i >= @expire_short_after }.each do | dns, info |
        puts "expire dns #{ info[ :im ] } #{ info[ :domain ] }" if @is_debug
        close_dns( dns )
      end
    end

    def check_expire_dsts( proxy )
      now = Time.new

      @dst_infos.select{ | dst, info | info[ :connected ] ? ( now.to_i - @updates[ dst ].to_i >= @expire_long_after ) : ( now.to_i - @updates[ dst ].to_i >= @expire_connecting ) }.each do | dst, info |
        puts "expire dst #{ info[ :im ] } #{ info[ :domain ] }" if @is_debug
        close_dst( dst )
      end

      if proxy && !proxy.closed? then
        proxy_info = @proxy_infos[ proxy ]
        overflow_infos = proxy_info[ :overflow_infos ].select{ | _, info | ( info[ :role ] == :dst ) && ( now.to_i - info[ :created_at ].to_i >= @expire_short_after ) }

        if overflow_infos.any? then
          overflow_infos.each do | dst, info |
            puts "expire overflow dst #{ proxy_info[ :im ] } #{ info[ :domain ] }"
            close_dst( dst )
            proxy_info[ :overflow_infos ].delete( dst )
          end

          if proxy_info[ :overflow_infos ].empty? then
            puts "resume proxy #{ proxy_info[ :im ] }"
            add_read( proxy )
          end
        end
      end
    end

    def check_expire_mems
      now = Time.new

      @mem_infos.select{ | mem, _ | now.to_i - @updates[ mem ].to_i >= @expire_short_after }.each do | mem, _ |
        puts "expire mem" if @is_debug
        close_mem( mem )
      end
    end

    def check_expire_p2s( im )
      now = Time.new

      @p2_infos.select{ | p2, _ | now.to_i - @updates[ p2 ].to_i >= @expire_long_after }.each do | p2, info |
        puts "expire p2 #{ info[ :im ] }" if @is_debug
        close_p2( p2 )
      end

      im_info = @im_infos[ im ]
      return unless im_info
      proxy = im_info[ :proxy ]

      if proxy && !proxy.closed? then
        proxy_info = @proxy_infos[ proxy ]
        overflow_infos = proxy_info[ :overflow_infos ].select{ | _, info | ( info[ :role ] == :p2 ) && ( now.to_i - info[ :created_at ].to_i >= @expire_short_after ) }

        if overflow_infos.any? then
          overflow_infos.each do | p2, info |
            puts "expire overflow p2 #{ im } #{ info[ :p2_id ] }"
            close_p2( p2 )
            proxy_info[ :overflow_infos ].delete( p2 )
          end

          if proxy_info[ :overflow_infos ].empty? then
            puts "resume proxy #{ im }"
            add_read( proxy )
          end
        end
      end
    end

    def check_expire_proxies
      now = Time.new

      @proxy_infos.select{ | proxy, _ | now.to_i - @updates[ proxy ].to_i >= @expire_long_after }.each do | proxy, info |
        puts "expire proxy #{ info[ :im ] }"
        close_proxy( proxy )
      end
    end

    def check_expire_rsvs
      now = Time.new

      @rsv_infos.select{ | rsv, _ | now.to_i - @updates[ rsv ].to_i >= @expire_short_after }.each do | rsv, info |
        puts "expire rsv #{ info[ :im ] } #{ info[ :domain ] }" if @is_debug
        close_rsv( rsv )
      end
    end

    def check_expire_srcs( proxy )
      return if proxy.nil? || proxy.closed?
      proxy_info = @proxy_infos[ proxy ]
      now = Time.new

      proxy_info[ :src_infos ].select{ | _, info | info[ :dst ].nil? && ( now.to_i - info[ :created_at ].to_i >= @expire_short_after ) }.each do | src_id, _ |
        puts "expire src info #{ proxy_info[ :im ] } #{ src_id }" if @is_debug
        proxy_info[ :src_infos ].delete( src_id )
      end
    end

    def close_dns( dns )
      return nil if dns.nil? || dns.closed?
      close_sock( dns )
      dns_info = @dns_infos.delete( dns )
      puts "close dns #{ dns_info[ :im ] } #{ dns_info[ :domain ] }" if @is_debug
      dns_info
    end

    def close_dst( dst )
      return nil if dst.nil? || dst.closed?
      close_sock( dst )
      dst_info = @dst_infos.delete( dst )
      puts "close dst #{ dst_info[ :im ] } #{ dst_info[ :domain ] } #{ dst_info[ :port ] }" if @is_debug
      proxy = dst_info[ :proxy ]

      unless proxy.closed? then
        proxy_info = @proxy_infos[ proxy ]
        src_id = dst_info[ :src_id ]

        if proxy_info[ :src_infos ].delete( src_id ) then
          puts "add h_dst_close #{ dst_info[ :im ] } #{ src_id }" if @is_debug
          msg = "#{ @h_dst_close }#{ [ src_id ].pack( 'Q>' ) }"
          add_proxy_wbuff( proxy, pack_a_chunk( msg ) )
        end

        overflow_info = proxy_info[ :overflow_infos ].delete( dst )

        if overflow_info && proxy_info[ :overflow_infos ].empty? then
          puts "resume proxy after close dst #{ proxy_info[ :im ] } #{ overflow_info[ :domain ] }"
          add_read( proxy )
        end
      end

      dst_info
    end

    def close_mem( mem )
      return nil if mem.nil? || mem.closed?
      close_sock( mem )
      @mem_infos.delete( mem )
    end

    def close_p2( p2 )
      return nil if p2.nil? || p2.closed?
      close_sock( p2 )
      p2_info = @p2_infos.delete( p2 )
      im = p2_info[ :im ]
      p2_id = p2_info[ :p2_id ]
      puts "close p2 #{ im } #{ p2_id }"
      im_info = @im_infos[ im ]

      if im_info then
        proxy = im_info[ :proxy ]

        unless proxy.closed? then
          proxy_info = @proxy_infos[ proxy ]

          if proxy_info[ :p2s ].delete( p2_id ) then
            puts "add h_p2_close #{ im } #{ p2_id }"
            msg = "#{ @h_p2_close }#{ [ p2_id ].pack( 'Q>' ) }"
            add_proxy_wbuff( proxy, pack_a_chunk( msg ) )
          end

          overflow_info = proxy_info[ :overflow_infos ].delete( p2 )

          if overflow_info && proxy_info[ :overflow_infos ].empty? then
            puts "resume proxy after close p2 #{ im } #{ p2_id }"
            add_read( proxy )
          end
        end
      end

      p2_info
    end

    def close_proxy( proxy )
      return nil if proxy.nil? || proxy.closed?
      close_sock( proxy )
      proxy_info = @proxy_infos.delete( proxy )
      puts "close proxy #{ proxy_info[ :addrinfo ].ip_unpack.inspect } #{ proxy_info[ :im ] }" if @is_debug
      proxy_info[ :src_infos ].values.each{ | info | close_dst( info[ :dst ] ) }
      proxy_info[ :p2s ].values.each{ | p2 | close_p2( p2 ) }
      proxy_info
    end

    def close_rsv( rsv )
      return nil if rsv.nil? || rsv.closed?
      close_sock( rsv )
      rsv_info = @rsv_infos.delete( rsv )
      puts "close rsv #{ rsv_info[ :im ] } #{ rsv_info[ :domain ] }" if @is_debug
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
      im = proxy_info[ :im ]
      return unless im
      h = data[ 0 ]

      case h
      when @h_a_new_source then
        return if data.bytesize < 9
        check_expire_srcs( proxy )
        src_id = data[ 1, 8 ].unpack( 'Q>' ).first
        domain_port = data[ 9..-1 ]
        puts "got h_a_new_source #{ im } #{ src_id } #{ domain_port.inspect }" if @is_debug

        src_info = {
          created_at: Time.new,
          dst: nil,
          rbuff: ''
        }

        proxy_info[ :src_infos ][ src_id ] = src_info
        resolve_domain_port( domain_port, src_id, proxy, im )
      when @h_p1_close then
        return if data.bytesize < 9
        p2_id = data[ 1, 8 ].unpack( 'Q>' ).first
        puts "got h_p1_close #{ im } #{ p2_id }"
        p2 = proxy_info[ :p2s ].delete( p2_id )
        set_p2_closing( p2 )
      when @h_p2_traffic then
        return if data.bytesize < 9
        p2_id = data[ 1, 8 ].unpack( 'Q>' ).first
        data = data[ 9..-1 ]
        # puts "got h_p2_traffic #{ im } #{ p2_id } #{ data.bytesize }" if @is_debug
        p2 = proxy_info[ :p2s ][ p2_id ]
        add_p2_wbuff( p2, data )
      when @h_query then
        return if data.bytesize < 10
        near_id, type = data[ 1, 9 ].unpack( 'Q>C' )
        return unless [ 1, 28 ].include?( type )
        domain = data[ 10..-1 ]
        return if domain.nil? || domain.empty?
        puts "got h_query #{ im } #{ near_id } #{ type } #{ domain.inspect }" if @is_debug
        new_a_rsv( domain, near_id, type, proxy, im )
      when @h_src_close then
        return if data.bytesize < 9
        src_id = data[ 1, 8 ].unpack( 'Q>' ).first
        puts "got h_src_close #{ im } #{ src_id }" if @is_debug
        src_info = proxy_info[ :src_infos ].delete( src_id )
        set_dst_closing( src_info[ :dst ] ) if src_info
      when @h_traffic then
        return if data.bytesize < 3
        src_id = data[ 1, 8 ].unpack( 'Q>' ).first
        data = data[ 9..-1 ]
        # puts "got h_traffic #{ im } #{ src_id } #{ data.bytesize }" if @is_debug
        src_info = proxy_info[ :src_infos ][ src_id ]

        if src_info then
          dst = src_info[ :dst ]

          if dst then
            add_dst_wbuff( dst, data )
          else
            puts "add src info rbuff #{ im } #{ data.bytesize }" if @is_debug
            src_info[ :rbuff ] << data

            if src_info[ :rbuff ].bytesize >= WBUFF_LIMIT then
              puts "src rbuff full"
              close_proxy( proxy )
            end
          end
        end
      when @h_p1_overflow then
        return if data.bytesize < 9
        p2_id = data[ 1, 8 ].unpack( 'Q>' ).first
        puts "got h_p1_overflow #{ im } #{ p2_id }"
        p2 = proxy_info[ :p2s ][ p2_id ]

        if p2 && !p2.closed? then
          @reads.delete( p2 )
          p2_info = @p2_infos[ p2 ]
          p2_info[ :paused ] = true
        end
      when @h_p1_underhalf then
        return if data.bytesize < 9
        p2_id = data[ 1, 8 ].unpack( 'Q>' ).first
        puts "got h_p1_underhalf #{ im } #{ p2_id }"
        p2 = proxy_info[ :p2s ][ p2_id ]

        if p2 && !p2.closed? then
          add_read( p2 )
          p2_info = @p2_infos[ p2 ]
          p2_info[ :paused ] = false
        end
      when @h_src_overflow then
        return if data.bytesize < 9
        src_id = data[ 1, 8 ].unpack( 'Q>' ).first
        puts "got h_src_overflow #{ im } #{ src_id }"
        src_info = proxy_info[ :src_infos ][ src_id ]

        if src_info then
          dst = src_info[ :dst ]

          if dst && !dst.closed? then
            @reads.delete( dst )
            dst_info = @dst_infos[ dst ]
            dst_info[ :paused ] = true
          end
        end
      when @h_src_underhalf then
        return if data.bytesize < 9
        src_id = data[ 1, 8 ].unpack( 'Q>' ).first
        puts "got h_src_underhalf #{ im } #{ src_id }"
        src_info = proxy_info[ :src_infos ][ src_id ]

        if src_info then
          dst = src_info[ :dst ]

          if dst && !dst.closed? then
            add_read( dst )
            dst_info = @dst_infos[ dst ]
            dst_info[ :paused ] = false
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

    def init_im_infos( ims, p2d_host, p2d_port )
      ims.sort.each_with_index do | im, i |
        @im_infos[ im ] = {
          addrinfo: nil,
          in: 0,
          out: 0,
          p2d: nil,
          p2d_host: p2d_host,
          p2d_port: p2d_port + i,
          proxy: nil
        }
      end
    end

    def loop_check_traff
      if @reset_traff_day > 0 then
        Thread.new do
          loop do
            sleep CHECK_TRAFF_INTERVAL
            now = Time.new

            if ( now.day == @reset_traff_day ) && ( now.hour == 0 ) then
              msg = { message_type: 'reset-traffic' }
              send_data( @info, JSON.generate( msg ), @infod_addr )
            end
          end
        end
      end
    end

    def loop_heartbeat
      Thread.new do
        loop do
          sleep HEARTBEAT_INTERVAL
          msg = { message_type: 'heartbeat' }
          send_data( @info, JSON.generate( msg ), @infod_addr )
        end
      end
    end

    def new_a_dst( domain, ip, port, src_id, proxy )
      return if proxy.nil? || proxy.closed?
      proxy_info = @proxy_infos[ proxy ]
      im = proxy_info[ :im ]
      src_info = proxy_info[ :src_infos ][ src_id ]
      return unless src_info

      check_expire_dsts( proxy )

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
        paused: false,
        port: port,
        proxy: proxy,
        rbuffs: [],
        src_id: src_id,
        wbuff: src_info[ :rbuff ].dup
      }

      @dst_infos[ dst ] = dst_info
      add_read( dst, :dst )
      add_write( dst )
      src_info[ :dst ] = dst
    end

    def new_a_infod( infod_port )
      infod_ip = '127.0.0.1'
      infod_addr = Socket.sockaddr_in( infod_port, infod_ip )
      infod = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      infod.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 ) if RUBY_PLATFORM.include?( 'linux' )
      infod.bind( infod_addr )
      puts "infod bind on #{ infod_ip } #{ infod_port }"
      add_read( infod, :infod )
      info = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      @infod_addr = infod_addr
      @infod = infod
      @info = info
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

    def new_a_rsv( domain, near_id, type, proxy, im )
      check_expire_rsvs
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

    def new_a_p2d( p2d_host, p2d_port, im, proxy )
      begin
        p2d = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
        p2d.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
        p2d.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 ) if RUBY_PLATFORM.include?( 'linux' )
        p2d.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_FASTOPEN, 5 ) if @is_server_fastopen
        p2d.bind( Socket.sockaddr_in( p2d_port, p2d_host ) )
        p2d.listen( 5 )
        puts "p2d listen on #{ p2d_host } #{ p2d_port } #{ im }"
        @p2d_infos[ p2d ] = { im: im }
        add_read( p2d, :p2d )
      rescue Exception => e
        puts "new a p2d #{ e.class }"
      end

      p2d
    end

    def new_a_proxyd( proxyd_port )
      proxyd_ip = '0.0.0.0'
      proxyd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      proxyd.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
      proxyd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 ) if RUBY_PLATFORM.include?( 'linux' )
      proxyd.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_FASTOPEN, BACKLOG ) if @is_server_fastopen
      proxyd.bind( Socket.sockaddr_in( proxyd_port, proxyd_ip ) )
      proxyd.listen( BACKLOG )
      puts "proxyd listen on #{ proxyd_ip } #{ proxyd_port }"
      add_read( proxyd, :proxyd )
    end

    def pack_a_chunk( msg )
      "#{ [ msg.bytesize ].pack( 'n' ) }#{ msg }"
    end

    def pack_p2_traffic( p2_id, data )
      chunks = ''

      loop do
        part = data[ 0, 65526 ]
        # puts "add h_p2_traffic #{ p2_id } #{ part.bytesize }" if @is_debug
        msg = "#{ @h_p2_traffic }#{ [ p2_id ].pack( 'Q>' ) }#{ part }"
        chunks << pack_a_chunk( msg )
        data = data[ part.bytesize..-1 ]
        break if data.empty?
      end

      chunks
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

      im = dst_info[ :im ]
      im_info = @im_infos[ im ]
      im_info[ :in ] += data.bytesize if im_info
      src_id = dst_info[ :src_id ]
      add_proxy_wbuff( proxy, pack_traffic( src_id, data ) )
      proxy_info = @proxy_infos[ proxy ]

      if proxy_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        puts "pause dst #{ im } #{ src_id } #{ dst_info[ :domain ] }"
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
      when 'heartbeat' then
        @proxy_infos.select{ | _, info | info[ :im ] }.each{ | proxy, _ | add_proxy_wbuff( proxy, pack_a_chunk( @h_heartbeat ) ) }
      when 'reset-traffic' then
        puts "reset traffic"
        @im_infos.each{ | _, info | info[ :in ] = info[ :out ] = 0 }
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
      im_arr = []

      @im_infos.select{ | _, info | info[ :addrinfo ] }.sort.each do | im, info |
        im_arr << {
          im: im,
          addrinfo: info[ :addrinfo ].ip_unpack,
          in: info[ :in ],
          out: info[ :out ],
          p2d_host: info[ :p2d_host ],
          p2d_port: info[ :p2d_port ]
        }
      end

      msg = {
        resolv_caches: @resolv_caches.sort,
        sizes: {
          reads: @reads.size,
          writes: @writes.size,
          roles: @roles.size,
          updates: @updates.size,
          proxy_infos: @proxy_infos.size,
          im_infos: @im_infos.size,
          mem_infos: @mem_infos.size,
          dst_infos: @dst_infos.size,
          dns_infos: @dns_infos.size,
          rsv_infos: @rsv_infos.size,
          resolv_caches: @resolv_caches.size,
          p2d_infos: @p2d_infos.size,
          p2_infos: @p2_infos.size
        },
        updates_limit: @updates_limit,
        eliminate_count: @eliminate_count,
        im_arr: im_arr
      }

      add_mem_wbuff( mem, JSON.generate( msg ) )
    end

    def read_memd( memd )
      check_expire_mems

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

    def read_p2( p2 )
      begin
        data = p2.read_nonblock( READ_SIZE )
      rescue Errno::ENOTCONN => e
        return
      rescue Exception => e
        close_p2( p2 )
        return
      end

      set_update( p2 )
      p2_info = @p2_infos[ p2 ]
      im = p2_info[ :im ]
      # puts "read p2 #{ im } #{ data.bytesize }" if @is_debug
      im_info = @im_infos[ im ]

      unless im_info then
        close_p2( p2 )
        return
      end

      proxy = im_info[ :proxy ]

      if proxy.nil? || proxy.closed? then
        close_p2( p2 )
        return
      end

      p2_id = p2_info[ :p2_id ]
      add_proxy_wbuff( proxy, pack_p2_traffic( p2_id, data ) )
      proxy_info = @proxy_infos[ proxy ]

      if proxy_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        puts "pause p2 #{ im } #{ p2_id }"
        @reads.delete( p2 )
        proxy_info[ :pause_p2_ids ][ p2 ] = p2_id
      end
    end

    def read_p2d( p2d )
      p2d_info = @p2d_infos[ p2d ]
      im = p2d_info[ :im ]
      check_expire_p2s( im )

      begin
        p2, addrinfo = p2d.accept_nonblock
      rescue Exception => e
        puts "p2d accept #{ e.class }"
        return
      end

      p2_id = rand( ( 2 ** 64 ) - 2 ) + 1

      p2_info = {
        addrinfo: addrinfo,
        im: im,
        p2_id: p2_id,
        paused: false,
        wbuff: ''
      }

      @p2_infos[ p2 ] = p2_info
      add_read( p2, :p2 )
      im_info = @im_infos[ im ]
      return unless im_info
      proxy = im_info[ :proxy ]
      return if proxy.nil? || proxy.closed?
      proxy_info = @proxy_infos[ proxy ]
      proxy_info[ :p2s ][ p2_id ] = p2
      puts "add h_a_new_p2 #{ im } #{ p2_id }"
      msg = "#{ @h_a_new_p2 }#{ [ p2_id ].pack( 'Q>' ) }"
      add_proxy_wbuff( proxy, pack_a_chunk( msg ) )
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

      if data.bytesize <= 65526 then
        rsv_info = @rsv_infos[ rsv ]
        proxy = rsv_info[ :proxy ]
        near_id = rsv_info[ :near_id ]
        puts "add h_response #{ rsv_info[ :im ] } #{ near_id } #{ rsv_info[ :domain ] } #{ data.bytesize }" if @is_debug
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
      im = proxy_info[ :im ]
      data = "#{ proxy_info[ :rbuff ] }#{ data }"

      unless im then
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

        if @im_infos.any? && !@im_infos.include?( im ) then
          puts "unknown im #{ im.inspect }"
          return
        end

        puts "got im #{ im }"
        proxy_info[ :im ] = im
        im_info = @im_infos[ im ]

        if im_info then
          im_info[ :proxy ] = proxy
          im_info[ :addrinfo ] = proxy_info[ :addrinfo ]
          im_info[ :p2d ] = new_a_p2d( im_info[ :p2d_host ], im_info[ :p2d_port ], im, proxy ) unless im_info[ :p2d ]
        end

        add_proxy_wbuff( proxy, pack_a_chunk( @h_heartbeat ) )
        data = data[ ( @head_len + 1 + len )..-1 ]
        return if data.empty?
      end

      im_info = @im_infos[ im ]
      im_info[ :in ] += data.bytesize if im_info
      msgs, part = decode_to_msgs( data )
      msgs.each{ | msg | deal_msg( msg, proxy ) }
      proxy_info[ :rbuff ] = part
    end

    def read_proxyd( proxyd )
      check_expire_proxies

      begin
        proxy, addrinfo = proxyd.accept_nonblock
      rescue Exception => e
        puts "accept a proxy #{ e.class }"
        return
      end

      puts "accept a proxy #{ addrinfo.ip_unpack.inspect }"

      proxy_info = {
        addrinfo: addrinfo,
        im: nil,
        overflow_infos: {}, # sock => { :created_at :domain :p2_id :role(:dst/:p2) }
        pause_domains: {},  # dst => domain
        p2s: {},            # p2_id => p2
        pause_p2_ids: {},   # p2 => p2_id
        rbuff: '',
        src_infos: {},      # src_id => { :created_at :dst :rbuff }
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

        if Time.new - created_at < @expire_resolv_cache then
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

      check_expire_dnses
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

    def set_p2_closing( p2 )
      return if p2.nil? || p2.closed?
      p2_info = @p2_infos[ p2 ]
      return if p2_info.nil? || p2_info[ :closing ]
      p2_info[ :closing ] = true
      add_write( p2 )
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
          when :p2
            close_p2( _sock )
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
      im = dst_info[ :im ]
      im_info = @im_infos[ im ]
      im_info[ :out ] += written if im_info
      data = data[ written..-1 ]
      dst_info[ :wbuff ] = data
      proxy = dst_info[ :proxy ]

      if proxy.closed? then
        close_dst( dst )
        return
      end

      proxy_info = @proxy_infos[ proxy ]
      overflow_info = proxy_info[ :overflow_infos ][ dst ]

      if overflow_info && ( dst_info[ :wbuff ].bytesize < RESUME_BELOW ) then
        puts "delete overflow dst #{ im } #{ overflow_info[ :domain ] }"
        proxy_info[ :overflow_infos ].delete( dst )

        if proxy_info[ :overflow_infos ].empty? then
          puts "resume proxy #{ im }"
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

    def write_p2( p2 )
      if p2.closed? then
        puts "write closed p2?"
        return
      end

      p2_info = @p2_infos[ p2 ]
      data = p2_info[ :wbuff ]

      if data.empty? then
        if p2_info[ :closing ] then
          close_p2( p2 )
        else
          @writes.delete( p2 )
        end

        return
      end

      begin
        written = p2.write_nonblock( data )
      rescue Errno::EINPROGRESS
        return
      rescue Exception => e
        close_p2( p2 )
        return
      end

      set_update( p2 )
      data = data[ written..-1 ]
      p2_info[ :wbuff ] = data
      im = p2_info[ :im ]
      im_info = @im_infos[ im ]

      unless im_info then
        close_p2( p2 )
        return
      end

      proxy = im_info[ :proxy ]

      if proxy.nil? || proxy.closed? then
        close_p2( p2 )
        return
      end

      proxy_info = @proxy_infos[ proxy ]
      overflow_info = proxy_info[ :overflow_infos ][ p2 ]

      if overflow_info && ( p2_info[ :wbuff ].bytesize < RESUME_BELOW ) then
        puts "delete overflow p2 #{ im } #{ overflow_info[ :p2_id ] }"
        proxy_info[ :overflow_infos ].delete( p2 )

        if proxy_info[ :overflow_infos ].empty? then
          puts "resume proxy #{ im }"
          add_read( proxy )
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
        written = proxy.write_nonblock( data )
      rescue Errno::EINPROGRESS
        return
      rescue Exception => e
        close_proxy( proxy )
        return
      end

      set_update( proxy )
      im = proxy_info[ :im ]
      im_info = @im_infos[ im ]
      im_info[ :out ] += written if im_info
      data = data[ written..-1 ]
      proxy_info[ :wbuff ] = data

      if proxy_info[ :wbuff ].bytesize < RESUME_BELOW then
        if proxy_info[ :pause_domains ].any? then
          proxy_info[ :pause_domains ].each do | dst, domain |
            dst_info = @dst_infos[ dst ]

            if dst_info && !dst_info[ :paused ] then
              puts "resume dst #{ im } #{ dst_info[ :src_id ] } #{ domain }"
              add_read( dst )
            end
          end

          proxy_info[ :pause_domains ].clear
        end

        if proxy_info[ :pause_p2_ids ].any? then
          proxy_info[ :pause_p2_ids ].each do | p2, p2_id |
            p2_info = @p2_infos[ p2 ]

            if p2_info && !p2_info[ :paused ] then
              puts "resume p2 #{ im } #{ p2_id }"
              add_read( p2 )
            end
          end

          proxy_info[ :pause_p2_ids ].clear
        end
      end
    end

  end
end
