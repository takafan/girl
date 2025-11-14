module Girl
  class ProxydWorker
    include Dns

    def initialize(
      proxyd_port,
      bigd_port,
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
      h_dst_switch_to_big,
      h_p2_switch_to_big,
      h_src_switch_to_big,
      h_p1_switch_to_big,
      expire_connecting,
      expire_long_after,
      expire_resolv_cache,
      expire_short_after,
      is_debug,
      is_server_fastopen)
      @nameserver_addrs = nameservers.map{|n| Socket.sockaddr_in(53, n)}
      @reset_traff_day = reset_traff_day
      @update_roles = [:big, :dns, :dst, :mem, :p2, :proxy, :rsv] # 参与淘汰的角色
      @updates_limit = 1010 - ims.size # 淘汰池上限，1015(mac) - [bigd info infod memd proxyd] - p2ds
      @eliminate_count = 0 # 淘汰次数
      @reads = []          # 读池
      @writes = []         # 写池
      @roles = {}          # sock => :big / :bigd / :dns / :dst / :infod / :mem / :memd / :p2 / :p2d / :proxy / :proxyd / :rsv
      @updates = {}        # sock => updated_at
      @proxy_infos = {}    # proxy => {:addrinfo :im :rbuff :wbuff}
      @big_infos = {}      # big => {:addrinfo :im :overflowing :rbuff :wbuff}
      @im_infos = {}       # im => {:addrinfo :big :big_connect_at :in :out :p2d :p2d_host :p2d_port :proxy :proxy_connect_at}
      @src_infos = {}      # src_id => {:created_at :dst :im :rbuff}
      @mem_infos = {}      # mem => {:wbuff}
      @dst_infos = {}      # dst => {:closing :connected :domain :im :in :ip :is_big :overflowing :port :rbuffs :src_id :switched :wbuff :wpend}
      @dns_infos = {}      # dns => {:domain :im :port :src_id}
      @rsv_infos = {}      # rsv => {:domain :im :near_id}
      @resolv_caches = {}  # domain => [ip created_at]
      @p2d_infos = {}      # p2d => {:im}
      @p2_infos = {}       # p2 => {:addrinfo :closing :im :in :is_big :overflowing :p2_id :switched :wbuff :wpend}
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
      @h_dst_switch_to_big = h_dst_switch_to_big
      @h_p2_switch_to_big = h_p2_switch_to_big
      @h_src_switch_to_big = h_src_switch_to_big
      @h_p1_switch_to_big = h_p1_switch_to_big
      @expire_connecting = expire_connecting
      @expire_long_after = expire_long_after
      @expire_resolv_cache = expire_resolv_cache
      @expire_short_after = expire_short_after
      @is_debug = is_debug
      @is_server_fastopen = is_server_fastopen
      init_im_infos(ims, p2d_host, p2d_port)
      new_a_proxyd(proxyd_port)
      new_a_bigd(bigd_port)
      new_a_infod(proxyd_port)
      new_a_memd(memd_port)
    end

    def looping
      puts "looping"
      loop_heartbeat
      loop_check_traff

      loop do
        rs, ws = IO.select(@reads, @writes)

        rs.each do |sock|
          role = @roles[sock]

          case role
          when :big
            read_big(sock)
          when :bigd
            read_bigd(sock)
          when :dns
            read_dns(sock)
          when :dst
            read_dst(sock)
          when :infod
            read_infod(sock)
          when :mem
            read_mem(sock)
          when :memd
            read_memd(sock)
          when :p2
            read_p2(sock)
          when :p2d
            read_p2d(sock)
          when :rsv
            read_rsv(sock)
          when :proxy
            read_proxy(sock)
          when :proxyd
            read_proxyd(sock)
          else
            close_sock(sock)
          end
        end

        ws.each do |sock|
          role = @roles[sock]

          case role
          when :big
            write_big(sock)
          when :dst
            write_dst(sock)
          when :mem
            write_mem(sock)
          when :p2
            write_p2(sock)
          when :proxy
            write_proxy(sock)
          else
            close_sock(sock)
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

    def add_big_wbuff(big, data)
      return if big.nil? || big.closed? || data.nil? || data.empty?
      big_info = @big_infos[big]
      big_info[:wbuff] << data
      bytesize = big_info[:wbuff].bytesize
      im = big_info[:im]

      if bytesize >= CLOSE_ABOVE
        puts "close overflow big #{im}"
        close_big(big)
        return
      end

      if !big_info[:overflowing] && (bytesize >= WBUFF_LIMIT)
        puts "big overflow #{im}"
        big_info[:overflowing] = true
      end

      add_write(big)
      big_info[:overflowing]
    end

    def add_dst_wbuff(dst, data)
      return if dst.nil? || dst.closed? || data.nil? || data.empty?
      dst_info = @dst_infos[dst]
      dst_info[:wbuff] << data
      bytesize = dst_info[:wbuff].bytesize
      im = dst_info[:im]
      domain = dst_info[:domain]

      if bytesize >= CLOSE_ABOVE
        puts "close overflow dst #{im} #{domain}"
        close_dst(dst)
        return
      end

      if !dst_info[:overflowing] && (bytesize >= WBUFF_LIMIT)
        puts "dst overflow #{im} #{domain}"
        dst_info[:overflowing] = true
        im_info = @im_infos[im]

        if im_info
          big = im_info[:big]

          if big
            puts 'pause big'
            @reads.delete(big)
          end
        end
      end

      add_write(dst)
    end

    def add_dst_wpend(dst, data)
      return if dst.nil? || dst.closed? || data.nil? || data.empty?
      dst_info = @dst_infos[dst]
      puts "add dst wpend #{data.bytesize}" if @is_debug
      dst_info[:wpend] << data
      bytesize = dst_info[:wpend].bytesize
      im = dst_info[:im]
      domain = dst_info[:domain]

      if bytesize >= CLOSE_ABOVE
        puts "dst wpend full"
        close_dst(dst)
        return
      end

      if !dst_info[:overflowing] && (bytesize >= WBUFF_LIMIT)
        puts "dst overflow #{im} #{domain}"
        dst_info[:overflowing] = true
        im_info = @im_infos[im]

        if im_info
          big = im_info[:big]

          if big
            puts 'pause big'
            @reads.delete(big)
          end
        end
      end
    end

    def add_mem_wbuff(mem, data)
      return if mem.nil? || mem.closed? || data.nil? || data.empty?
      mem_info = @mem_infos[mem]
      mem_info[:wbuff] << data
      add_write(mem)
    end

    def add_p2_wbuff(p2, data)
      return if p2.nil? || p2.closed? || data.nil? || data.empty?
      p2_info = @p2_infos[p2]
      p2_info[:wbuff] << data
      bytesize = p2_info[:wbuff].bytesize
      im = p2_info[:im]
      p2_id = p2_info[:p2_id]

      if bytesize >= CLOSE_ABOVE
        puts "close overflow p2 #{im} #{p2_id}"
        close_p2(p2)
        return
      end

      if !p2_info[:overflowing] && (bytesize >= WBUFF_LIMIT)
        puts "p2 overflow #{im} #{p2_id}"
        p2_info[:overflowing] = true
        im_info = @im_infos[im]

        if im_info
          big = im_info[:big]

          if big
            puts 'pause big'
            @reads.delete(big)
          end
        end
      end

      add_write(p2)
    end

    def add_p2_wpend(p2, data)
      return if p2.nil? || p2.closed? || data.nil? || data.empty?
      p2_info = @p2_infos[p2]
      puts "add p2 wpend #{data.bytesize}" if @is_debug
      p2_info[:wpend] << data
      bytesize = p2_info[:wpend].bytesize
      im = p2_info[:im]
      p2_id = p2_info[:p2_id]

      if bytesize >= CLOSE_ABOVE
        puts "p2 wpend full"
        close_p2(p2)
        return
      end

      if !p2_info[:overflowing] && (bytesize >= WBUFF_LIMIT)
        puts "p2 overflow #{im} #{p2_id}"
        p2_info[:overflowing] = true
        im_info = @im_infos[im]

        if im_info
          big = im_info[:big]

          if big
            puts 'pause big'
            @reads.delete(big)
          end
        end
      end
    end

    def add_proxy_wbuff(proxy, data)
      return if proxy.nil? || proxy.closed? || data.nil? || data.empty?
      proxy_info = @proxy_infos[proxy]
      proxy_info[:wbuff] << data
      bytesize = proxy_info[:wbuff].bytesize
      im = proxy_info[:im]

      if bytesize >= CLOSE_ABOVE
        puts "close overflow proxy #{im}"
        close_proxy(proxy)
        return
      end

      add_write(proxy)
    end

    def add_read(sock, role = nil)
      return if sock.nil? || sock.closed? || @reads.include?(sock)
      @reads << sock

      if role
        @roles[sock] = role
      else
        role = @roles[sock]
      end

      if @update_roles.include?(role)
        set_update(sock)
      end
    end

    def add_write(sock)
      return if sock.nil? || sock.closed? || @writes.include?(sock)
      @writes << sock
      role = @roles[sock]
      set_update(sock) if @update_roles.include?(role)
    end

    def check_expire_bigs
      now = Time.new

      @big_infos.select{|big, _| now.to_i - @updates[big].to_i >= @expire_long_after}.each do |big, info|
        puts "expire big #{info[:im]}"
        close_big(big)
      end
    end

    def check_expire_dnses
      now = Time.new

      @dns_infos.select{|dns, _| now.to_i - @updates[dns].to_i >= @expire_short_after}.each do |dns, info|
        puts "expire dns #{info[:im]} #{info[:domain]}" if @is_debug
        close_dns(dns)
      end
    end

    def check_expire_dsts
      now = Time.new

      @dst_infos.select{|dst, info| info[:connected] ? (now.to_i - @updates[dst].to_i >= @expire_long_after) : (now.to_i - @updates[dst].to_i >= @expire_connecting)}.each do |dst, info|
        puts "expire dst #{info[:im]} #{info[:domain]}" if @is_debug
        close_dst(dst)
      end
    end

    def check_expire_mems
      now = Time.new

      @mem_infos.select{|mem, _| now.to_i - @updates[mem].to_i >= @expire_short_after}.each do |mem, _|
        puts "expire mem" if @is_debug
        close_mem(mem)
      end
    end

    def check_expire_p2s
      now = Time.new

      @p2_infos.select{|p2, _| now.to_i - @updates[p2].to_i >= @expire_long_after}.each do |p2, info|
        puts "expire p2 #{info[:im]} #{info[:p2_id]}" if @is_debug
        close_p2(p2)
      end
    end

    def check_expire_proxies
      now = Time.new

      @proxy_infos.select{|proxy, _| now.to_i - @updates[proxy].to_i >= @expire_long_after}.each do |proxy, info|
        puts "expire proxy #{info[:im]}"
        close_proxy(proxy)
      end
    end

    def check_expire_rsvs
      now = Time.new

      @rsv_infos.select{|rsv, _| now.to_i - @updates[rsv].to_i >= @expire_short_after}.each do |rsv, info|
        puts "expire rsv #{info[:im]} #{info[:domain]}" if @is_debug
        close_rsv(rsv)
      end
    end

    def check_expire_srcs
      now = Time.new

      @src_infos.select{|_, info| info[:dst].nil? && (now.to_i - info[:created_at].to_i >= @expire_short_after)}.each do |src_id, info|
        puts "expire src info #{info[:im]} #{src_id}" if @is_debug
        @src_infos.delete(src_id)
      end
    end

    def close_big(big)
      return nil if big.nil? || big.closed?
      close_sock(big)
      big_info = @big_infos.delete(big)

      if big_info
        addrinfo = big_info[:addrinfo].ip_unpack.inspect
        im = big_info[:im]
        puts "close big #{addrinfo} #{im}" if @is_debug
      end

      big_info
    end

    def close_dns(dns)
      return nil if dns.nil? || dns.closed?
      close_sock(dns)
      dns_info = @dns_infos.delete(dns)

      if dns_info
        im = dns_info[:im]
        domain = dns_info[:domain]
        puts "close dns #{im} #{domain}" if @is_debug
      end

      dns_info
    end

    def close_dst(dst)
      return nil if dst.nil? || dst.closed?
      close_sock(dst)
      dst_info = @dst_infos.delete(dst)

      if dst_info
        im = dst_info[:im]
        src_id = dst_info[:src_id]
        domain = dst_info[:domain]
        @src_infos.delete(src_id)
        puts "close dst #{im} #{domain}" if @is_debug
        im_info = @im_infos[im]

        if im_info
          puts "add h_dst_close #{im} #{domain} #{src_id}" if @is_debug
          msg = "#{@h_dst_close}#{[src_id].pack('Q>')}"
          add_proxy_wbuff(im_info[:proxy], pack_a_chunk(msg))
        end
      end

      dst_info
    end

    def close_mem(mem)
      return nil if mem.nil? || mem.closed?
      close_sock(mem)
      @mem_infos.delete(mem)
    end

    def close_p2(p2)
      return nil if p2.nil? || p2.closed?
      close_sock(p2)
      p2_info = @p2_infos.delete(p2)

      if p2_info
        im = p2_info[:im]
        p2_id = p2_info[:p2_id]
        puts "close p2 #{im} #{p2_id}"
        im_info = @im_infos[im]

        if im_info
          puts "add h_p2_close #{im} #{p2_id}"
          msg = "#{@h_p2_close}#{[p2_id].pack('Q>')}"
          add_proxy_wbuff(im_info[:proxy], pack_a_chunk(msg))
        end
      end

      p2_info
    end

    def close_proxy(proxy)
      return nil if proxy.nil? || proxy.closed?
      close_sock(proxy)
      proxy_info = @proxy_infos.delete(proxy)

      if proxy_info
        addrinfo = proxy_info[:addrinfo].ip_unpack.inspect
        im = proxy_info[:im]
        puts "close proxy #{addrinfo} #{im}" if @is_debug
        @dst_infos.select{|_, info| info[:im] == im}.each{|dst, _| close_dst(dst)}
        @p2_infos.select{|_, info| info[:im] == im}.each{|p2, _| close_p2(p2)}
      end

      proxy_info
    end

    def close_rsv(rsv)
      return nil if rsv.nil? || rsv.closed?
      close_sock(rsv)
      rsv_info = @rsv_infos.delete(rsv)

      if rsv_info
        im = rsv_info[:im]
        domain = rsv_info[:domain]
        puts "close rsv #{im} #{domain}" if @is_debug
      end

      rsv_info
    end

    def close_sock(sock)
      return if sock.nil? || sock.closed?
      sock.close
      @reads.delete(sock)
      @writes.delete(sock)
      @updates.delete(sock)
      @roles.delete(sock)
    end

    def deal_big_msg(data, big)
      return if data.nil? || data.empty? || big.nil? || big.closed?
      big_info = @big_infos[big]
      im = big_info[:im]
      return unless im
      h = data[0]

      case h
      when @h_p2_traffic
        return if data.bytesize < 9
        p2_id = data[1, 8].unpack('Q>').first
        data = data[9..-1]
        # puts "big got h_p2_traffic #{im} #{p2_id} #{data.bytesize}" if @is_debug
        p2, p2_info = @p2_infos.find{|_, info| (info[:im] == im) && (info[:p2_id] == p2_id)}
        
        if p2_info
          if p2_info[:switched]
            add_p2_wbuff(p2, data)
          else
            add_p2_wpend(p2, data)
          end
        end
      when @h_traffic
        return if data.bytesize < 9
        src_id = data[1, 8].unpack('Q>').first
        data = data[9..-1]
        # puts "big got h_traffic #{im} #{src_id} #{data.bytesize}" if @is_debug
        src_info = @src_infos[src_id]

        if src_info
          dst = src_info[:dst]

          if dst
            dst_info = @dst_infos[dst]

            if dst_info
              if dst_info[:switched]
                add_dst_wbuff(dst, data)
              else
                add_dst_wpend(dst, data)
              end
            end
          end
        end
      end
    end

    def deal_msg(data, proxy)
      return if data.nil? || data.empty? || proxy.nil? || proxy.closed?
      proxy_info = @proxy_infos[proxy]
      im = proxy_info[:im]
      return unless im
      h = data[0]

      case h
      when @h_a_new_source
        return if data.bytesize < 9
        check_expire_srcs
        src_id = data[1, 8].unpack('Q>').first
        domain_port = data[9..-1]
        puts "got h_a_new_source #{im} #{src_id} #{domain_port.inspect}" if @is_debug
        @src_infos[src_id] = {
          created_at: Time.new,
          dst: nil,
          im: im,
          rbuff: ''
        }
        resolve_domain_port(domain_port, src_id)
      when @h_p1_close
        return if data.bytesize < 9
        p2_id = data[1, 8].unpack('Q>').first
        puts "got h_p1_close #{im} #{p2_id}"
        p2, _ = @p2_infos.find{|_, info| (info[:im] == im) && (info[:p2_id] == p2_id)}
        set_p2_closing(p2)
      when @h_p2_traffic
        return if data.bytesize < 9
        p2_id = data[1, 8].unpack('Q>').first
        data = data[9..-1]
        p2, _ = @p2_infos.find{|_, info| (info[:im] == im) && (info[:p2_id] == p2_id)}
        add_p2_wbuff(p2, data)
      when @h_query
        return if data.bytesize < 10
        near_id, type = data[1, 9].unpack('Q>C')
        return unless [1, 28].include?(type)
        domain = data[10..-1]
        return if domain.nil? || domain.empty?
        puts "got h_query #{im} #{near_id} #{type} #{domain.inspect}" if @is_debug
        new_a_rsv(domain, near_id, type, proxy, im)
      when @h_src_close
        return if data.bytesize < 9
        src_id = data[1, 8].unpack('Q>').first
        puts "got h_src_close #{im} #{src_id}" if @is_debug
        src_info = @src_infos.delete(src_id)
        set_dst_closing(src_info[:dst]) if src_info
      when @h_traffic
        return if data.bytesize < 9
        src_id = data[1, 8].unpack('Q>').first
        data = data[9..-1]
        src_info = @src_infos[src_id]

        if src_info
          dst = src_info[:dst]

          if dst
            add_dst_wbuff(dst, data)
          else
            puts "add src rbuff #{im} #{data.bytesize}" if @is_debug
            src_info[:rbuff] << data

            if src_info[:rbuff].bytesize >= CLOSE_ABOVE
              puts "src rbuff full"
              @src_infos.delete(src_id)
            end
          end
        end
      when @h_src_switch_to_big
        return if data.bytesize < 9
        src_id = data[1, 8].unpack('Q>').first
        puts "got h_src_switch_to_big #{src_id}" if @is_debug
        src_info = @src_infos[src_id]

        if src_info
          dst = src_info[:dst]

          if dst
            dst_info = @dst_infos[dst]

            if dst_info && !dst_info[:switched]
              dst_info[:switched] = true
              
              unless dst_info[:wpend].empty?
                data = dst_info[:wpend].dup
                domain = dst_info[:domain]
                puts "move dst wpend to wbuff #{domain} #{data.bytesize}"
                dst_info[:wpend].clear
                add_dst_wbuff(dst, data)
              end
            end
          end
        end
      when @h_p1_switch_to_big
        return if data.bytesize < 9
        p2_id = data[1, 8].unpack('Q>').first
        puts "got h_p1_switch_to_big #{p2_id}" if @is_debug
        p2, p2_info = @p2_infos.find{|_, info| (info[:im] == im) && (info[:p2_id] == p2_id)}

        if p2_info && !p2_info[:switched]
          p2_info[:switched] = true
          
          unless p2_info[:wpend].empty?
            data = p2_info[:wpend].dup
            puts "move p2 wpend to wbuff #{p2_id} #{data.bytesize}"
            p2_info[:wpend].clear
            add_p2_wbuff(p2, data)
          end
        end
      end
    end

    def decode_to_msgs(data)
      msgs = []
      part = ''

      loop do
        if data.bytesize <= 2
          part = data
          break
        end

        len = data[0, 2].unpack('n').first

        if len == 0
          puts "msg zero len?"
          break
        end

        if data.bytesize < (2 + len)
          part = data
          break
        end

        msgs << data[2, len]
        data = data[(2 + len)..-1]
        break if data.empty?
      end

      [msgs, part]
    end

    def init_im_infos(ims, p2d_host, p2d_port)
      ims.sort.each_with_index do |im, i|
        @im_infos[im] = {
          addrinfo: nil,
          big: nil,
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
      if @reset_traff_day > 0
        Thread.new do
          loop do
            sleep CHECK_TRAFF_INTERVAL
            now = Time.new

            if (now.day == @reset_traff_day) && (now.hour == 0)
              msg = {message_type: 'reset-traffic'}
              send_data(@info, JSON.generate(msg), @infod_addr)
            end
          end
        end
      end
    end

    def loop_heartbeat
      Thread.new do
        loop do
          sleep HEARTBEAT_INTERVAL
          msg = {message_type: 'heartbeat'}
          send_data(@info, JSON.generate(msg), @infod_addr)
        end
      end
    end

    def new_a_bigd(bigd_port)
      bigd_host = '0.0.0.0'
      bigd = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
      bigd.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
      bigd.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1) if RUBY_PLATFORM.include?('linux')
      bigd.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_FASTOPEN, BACKLOG) if @is_server_fastopen
      bigd.bind(Socket.sockaddr_in(bigd_port, bigd_host))
      bigd.listen(BACKLOG)
      puts "bigd listen on #{bigd_host} #{bigd_port}"
      add_read(bigd, :bigd)
    end

    def new_a_dst(domain, ip, port, src_id)
      src_info = @src_infos[src_id]
      return unless src_info
      im = src_info[:im]
      check_expire_dsts

      begin
        dst = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
      rescue Exception => e
        puts "new a dst #{e.class} #{im} #{domain}:#{port}"
        return
      end

      dst.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)

      begin
        destination_addr = Socket.sockaddr_in(port, ip)
        dst.connect_nonblock(destination_addr)
      rescue IO::WaitWritable
      rescue Exception => e
        puts "connect destination #{e.class} #{im} #{domain}:#{port}"
        dst.close
        return
      end

      dst_info = {
        closing: false,
        connected: false,
        domain: domain,
        im: im,
        in: 0,
        ip: ip,
        is_big: false, # 是否收流量大户
        overflowing: false,
        port: port,
        rbuffs: [],
        src_id: src_id,
        switched: false,
        wbuff: src_info[:rbuff].dup,
        wpend: ''
      }

      @dst_infos[dst] = dst_info
      add_read(dst, :dst)
      add_write(dst)
      src_info[:rbuff].clear
      src_info[:dst] = dst
    end

    def new_a_infod(infod_port)
      infod_host = '127.0.0.1'
      infod_addr = Socket.sockaddr_in(infod_port, infod_host)
      infod = Socket.new(Socket::AF_INET, Socket::SOCK_DGRAM, 0)
      infod.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1) if RUBY_PLATFORM.include?('linux')
      infod.bind(infod_addr)
      puts "infod bind on #{infod_host} #{infod_port}"
      add_read(infod, :infod)
      info = Socket.new(Socket::AF_INET, Socket::SOCK_DGRAM, 0)
      @infod_addr = infod_addr
      @infod = infod
      @info = info
    end

    def new_a_memd(memd_port)
      memd_host = '127.0.0.1'
      memd = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
      memd.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
      memd.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1) if RUBY_PLATFORM.include?('linux')
      memd.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_FASTOPEN, 5) if @is_server_fastopen
      memd.bind(Socket.sockaddr_in(memd_port, memd_host))
      memd.listen(5)
      puts "memd listen on #{memd_host} #{memd_port}"
      add_read(memd, :memd)
    end

    def new_a_rsv(domain, near_id, type, proxy, im)
      check_expire_rsvs
      rsv = Socket.new(Socket::AF_INET, Socket::SOCK_DGRAM, 0)

      begin
        data = pack_a_query(domain, type)
      rescue Exception => e
        puts "rsv pack a query #{e.class} #{e.message} #{domain}" if @is_debug
        return
      end

      begin
        @nameserver_addrs.each{|addr| rsv.sendmsg(data, 0, addr)}
      rescue Exception => e
        puts "rsv send data #{e.class}"
        rsv.close
        return
      end

      @rsv_infos[rsv] = {
        domain: domain,
        im: im,
        near_id: near_id
      }
      add_read(rsv, :rsv)
    end

    def new_a_p2d(p2d_host, p2d_port, im)
      begin
        p2d = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
        p2d.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
        p2d.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1) if RUBY_PLATFORM.include?('linux')
        p2d.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_FASTOPEN, 5) if @is_server_fastopen
        p2d.bind(Socket.sockaddr_in(p2d_port, p2d_host))
        p2d.listen(5)
        puts "p2d listen on #{p2d_host} #{p2d_port} #{im}"
        @p2d_infos[p2d] = {im: im}
        add_read(p2d, :p2d)
      rescue Exception => e
        puts "new a p2d #{e.class}"
      end

      p2d
    end

    def new_a_proxyd(proxyd_port)
      proxyd_host = '0.0.0.0'
      proxyd = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
      proxyd.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
      proxyd.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1) if RUBY_PLATFORM.include?('linux')
      proxyd.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_FASTOPEN, BACKLOG) if @is_server_fastopen
      proxyd.bind(Socket.sockaddr_in(proxyd_port, proxyd_host))
      proxyd.listen(BACKLOG)
      puts "proxyd listen on #{proxyd_host} #{proxyd_port}"
      add_read(proxyd, :proxyd)
    end

    def pack_a_chunk(msg)
      "#{[msg.bytesize].pack('n')}#{msg}"
    end

    def pack_p2_traffic(p2_id, data)
      chunks = ''

      loop do
        part = data[0, 65526]
        # puts "add h_p2_traffic #{p2_id} #{part.bytesize}" if @is_debug
        msg = "#{@h_p2_traffic}#{[p2_id].pack('Q>')}#{part}"
        chunks << pack_a_chunk(msg)
        data = data[part.bytesize..-1]
        break if data.empty?
      end

      chunks
    end

    def pack_traffic(src_id, data)
      chunks = ''

      loop do
        part = data[0, 65526]
        # puts "add h_traffic #{src_id} #{part.bytesize}" if @is_debug
        msg = "#{@h_traffic}#{[src_id].pack('Q>')}#{part}"
        chunks << pack_a_chunk(msg)
        data = data[part.bytesize..-1]
        break if data.empty?
      end

      chunks
    end

    def read_big(big)
      begin
        data = big.read_nonblock(READ_SIZE)
      rescue Errno::ENOTCONN => e
        return
      rescue Exception => e
        puts "read big #{e.class}" if @is_debug
        close_big(big)
        return
      end

      set_update(big)
      big_info = @big_infos[big]
      im = big_info[:im]
      data = "#{big_info[:rbuff]}#{data}"

      unless im
        if data.bytesize < @head_len + 1
          big_info[:rbuff] = data
          return
        end

        len = data[@head_len].unpack('C').first

        if len == 0
          puts "im zero len?"
          return
        end

        if data.bytesize < @head_len + 1 + len
          big_info[:rbuff] = data
          return
        end

        im = data[@head_len + 1, len]

        if @im_infos.any?
          im_info = @im_infos[im]

          unless im_info
            puts "unknown im #{im.inspect}"
            return
          end

          if im_info[:big] && !im_info[:big].closed?
            puts "big already alive #{im.inspect}"
            return
          end
        end

        puts "big got im #{im}"
        big_info[:im] = im

        if im_info
          im_info[:big] = big
          im_info[:big_connect_at] = Time.new
        end

        add_big_wbuff(big, pack_a_chunk(@h_heartbeat))
        data = data[(@head_len + 1 + len)..-1]
        return if data.empty?
      end

      im_info = @im_infos[im]
      im_info[:in] += data.bytesize if im_info
      msgs, part = decode_to_msgs(data)
      msgs.each{|msg| deal_big_msg(msg, big)}
      big_info[:rbuff] = part
    end

    def read_bigd(bigd)
      check_expire_bigs

      begin
        big, addrinfo = bigd.accept_nonblock
      rescue Exception => e
        puts "accept a big #{e.class}"
        return
      end

      puts "accept a big #{addrinfo.ip_unpack.inspect}"

      big_info = {
        addrinfo: addrinfo,
        im: nil,
        overflowing: false,
        rbuff: '',
        wbuff: ''
      }

      @big_infos[big] = big_info
      add_read(big, :big)
    end

    def read_dns(dns)
      begin
        data, addrinfo, rflags, *controls = dns.recvmsg
      rescue Exception => e
        puts "dns recvmsg #{e.class}"
        close_dns(dns)
        return
      end

      return if data.empty?

      begin
        ip = seek_ip(data)
      rescue Exception => e
        puts "seek ip #{e.class} #{e.message}"
        close_dns(dns)
        return
      end

      dns_info = @dns_infos[dns]
      domain = dns_info[:domain]

      if ip
        port = dns_info[:port]
        src_id = dns_info[:src_id]
        im = dns_info[:im]
        puts "got ip #{im} #{domain} #{ip}" if @is_debug
        new_a_dst(domain, ip, port, src_id)
        @resolv_caches[domain] = [ip, Time.new]
      else
        puts "no ip in answer #{domain}" if @is_debug
      end

      close_dns(dns)
    end

    def read_dst(dst)
      begin
        data = dst.read_nonblock(READ_SIZE)
      rescue Errno::ENOTCONN => e
        return
      rescue Exception => e
        puts "read dst #{e.class}" if @is_debug
        close_dst(dst)
        return
      end

      set_update(dst)
      dst_info = @dst_infos[dst]
      dst_info[:in] += data.bytesize
      im = dst_info[:im]
      src_id = dst_info[:src_id]
      domain = dst_info[:domain]
      im_info = @im_infos[im]

      unless im_info
        close_dst(dst)
        return
      end

      proxy = im_info[:proxy]

      if proxy.nil? || proxy.closed?
        close_dst(dst)
        return
      end

      if !dst_info[:is_big] && (dst_info[:in] >= READ_SIZE)
        puts "set dst is big #{im} #{src_id} #{domain}"
        dst_info[:is_big] = true
        msg = "#{@h_dst_switch_to_big}#{[src_id].pack('Q>')}"
        add_proxy_wbuff(proxy, pack_a_chunk(msg))
      end

      im_info[:in] += data.bytesize
      data = pack_traffic(src_id, data)

      if dst_info[:is_big]
        big = im_info[:big]

        if big.nil? || big.closed?
          close_dst(dst)
          return
        end

        overflowing = add_big_wbuff(big, data)

        if overflowing
          puts "big overflowing pause dst #{src_id} #{domain}"
          @reads.delete(dst)
        end
      else
        add_proxy_wbuff(proxy, data)
      end
    end

    def read_infod(infod)
      begin
        data, addrinfo, rflags, *controls = infod.recvmsg
      rescue Exception => e
        puts "infod recvmsg #{e.class}"
        return
      end

      return if data.empty?

      begin
        msg = JSON.parse(data, symbolize_names: true)
      rescue JSON::ParserError, EncodingError => e
        puts "read infod #{e.class}"
        return
      end

      message_type = msg[:message_type]

      case message_type
      when 'heartbeat'
        @proxy_infos.select{|_, info| info[:im]}.each{|proxy, _| add_proxy_wbuff(proxy, pack_a_chunk(@h_heartbeat))}
        @big_infos.select{|_, info| info[:im]}.each{|big, _| add_big_wbuff(big, pack_a_chunk(@h_heartbeat))}
      when 'reset-traffic'
        puts "reset traffic"
        @im_infos.each{|_, info| info[:in] = info[:out] = 0}
      end
    end

    def read_mem(mem)
      begin
        mem.read_nonblock(READ_SIZE)
      rescue Errno::ENOTCONN => e
        return
      rescue Exception => e
        close_mem(mem)
        return
      end

      set_update(mem)
      im_arr = []

      @im_infos.select{|_, info| info[:addrinfo]}.sort.each do |im, info|
        im_arr << {
          im: im,
          p2d_port: info[:p2d_port],
          p2d_host: info[:p2d_host],
          addrinfo: info[:addrinfo].ip_unpack,
          in: info[:in],
          out: info[:out],
          proxy_connect_at: info[:proxy_connect_at] ? info[:proxy_connect_at].strftime('%F %T') : '--',
          big_connect_at: info[:big_connect_at] ? info[:big_connect_at].strftime('%F %T') : '--'
        }
      end

      msg = {
        sizes: {
          reads: @reads.size,
          writes: @writes.size,
          roles: @roles.size,
          updates: @updates.size,
          im_infos: @im_infos.size,
          proxy_infos: @proxy_infos.size,
          big_infos: @big_infos.size,
          mem_infos: @mem_infos.size,
          src_infos: @src_infos.size,
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

      add_mem_wbuff(mem, JSON.generate(msg))
    end

    def read_memd(memd)
      check_expire_mems

      begin
        mem, addrinfo = memd.accept_nonblock
      rescue Exception => e
        puts "memd accept #{e.class}"
        return
      end

      mem_info = {
        wbuff: ''
      }

      @mem_infos[mem] = mem_info
      add_read(mem, :mem)
    end

    def read_p2(p2)
      begin
        data = p2.read_nonblock(READ_SIZE)
      rescue Errno::ENOTCONN => e
        return
      rescue Exception => e
        puts "read p2 #{e.class}" if @is_debug
        close_p2(p2)
        return
      end

      set_update(p2)
      p2_info = @p2_infos[p2]
      p2_info[:in] += data.bytesize
      im = p2_info[:im]
      p2_id = p2_info[:p2_id]
      im_info = @im_infos[im]

      unless im_info
        close_p2(p2)
        return
      end

      proxy = im_info[:proxy]

      if proxy.nil? || proxy.closed?
        close_p2(p2)
        return
      end

      if !p2_info[:is_big] && (p2_info[:in] >= READ_SIZE)
        puts "set p2 is big #{im} #{p2_id}"
        p2_info[:is_big] = true
        msg = "#{@h_p2_switch_to_big}#{[p2_id].pack('Q>')}"
        add_proxy_wbuff(proxy, pack_a_chunk(msg))
      end

      data = pack_p2_traffic(p2_id, data)

      if p2_info[:is_big]
        big = im_info[:big]

        if big.nil? || big.closed?
          close_p2(p2)
          return
        end

        overflowing = add_big_wbuff(big, data)

        if overflowing
          puts "big overflowing pause p2 #{p2_id}"
          @reads.delete(p2)
        end
      else
        add_proxy_wbuff(proxy, data)
      end
    end

    def read_p2d(p2d)
      check_expire_p2s

      begin
        p2, addrinfo = p2d.accept_nonblock
      rescue Exception => e
        puts "p2d accept #{e.class}"
        return
      end

      p2d_info = @p2d_infos[p2d]
      im = p2d_info[:im]
      p2_id = rand((2 ** 64) - 2) + 1
      @p2_infos[p2] = {
        addrinfo: addrinfo,
        closing: false,
        im: im,
        in: 0,
        is_big: false, # 是否收流量大户
        overflowing: false,
        p2_id: p2_id,
        switched: false,
        wbuff: '',
        wpend: ''
      }
      add_read(p2, :p2)
      im_info = @im_infos[im]
      return unless im_info
      puts "add h_a_new_p2 #{im} #{p2_id}"
      msg = "#{@h_a_new_p2}#{[p2_id].pack('Q>')}"
      add_proxy_wbuff(im_info[:proxy], pack_a_chunk(msg))
    end

    def read_rsv(rsv)
      begin
        data, addrinfo, rflags, *controls = rsv.recvmsg
      rescue Exception => e
        puts "rsv recvmsg #{e.class}"
        close_rsv(rsv)
        return
      end

      return if data.empty?

      if data.bytesize <= 65526
        rsv_info = @rsv_infos[rsv]
        im = rsv_info[:im]
        im_info = @im_infos[im]

        if im_info
          proxy = im_info[:proxy]

          if proxy.nil? || proxy.closed?
            close_rsv(rsv)
            return
          end

          near_id = rsv_info[:near_id]
          puts "add h_response #{im} #{near_id} #{rsv_info[:domain]} #{data.bytesize}" if @is_debug
          msg = "#{@h_response}#{[near_id].pack('Q>')}#{data}"
          add_proxy_wbuff(proxy, pack_a_chunk(msg))
        end
      else
        puts "response too big? #{data.bytesize}"
      end

      close_rsv(rsv)
    end

    def read_proxy(proxy)
      begin
        data = proxy.read_nonblock(READ_SIZE)
      rescue Errno::ENOTCONN => e
        return
      rescue Exception => e
        puts "read proxy #{e.class}" if @is_debug
        close_proxy(proxy)
        return
      end

      set_update(proxy)
      proxy_info = @proxy_infos[proxy]
      im = proxy_info[:im]
      data = "#{proxy_info[:rbuff]}#{data}"

      unless im
        if data.bytesize < @head_len + 1
          proxy_info[:rbuff] = data
          return
        end

        len = data[@head_len].unpack('C').first

        if len == 0
          puts "im zero len?"
          return
        end

        if data.bytesize < @head_len + 1 + len
          proxy_info[:rbuff] = data
          return
        end

        im = data[@head_len + 1, len]

        if @im_infos.any?
          im_info = @im_infos[im]

          unless im_info
            puts "unknown im #{im.inspect}"
            return
          end

          if im_info[:proxy] && !im_info[:proxy].closed?
            puts "proxy already alive #{im.inspect}"
            return
          end
        end

        puts "proxy got im #{im}"
        proxy_info[:im] = im
        
        if im_info
          im_info[:proxy] = proxy
          im_info[:proxy_connect_at] = Time.new
          im_info[:addrinfo] = proxy_info[:addrinfo]
          im_info[:p2d] = new_a_p2d(im_info[:p2d_host], im_info[:p2d_port], im) unless im_info[:p2d]
        end

        add_proxy_wbuff(proxy, pack_a_chunk(@h_heartbeat))
        data = data[(@head_len + 1 + len)..-1]
        return if data.empty?
      end

      im_info = @im_infos[im]
      im_info[:in] += data.bytesize if im_info
      msgs, part = decode_to_msgs(data)
      msgs.each{|msg| deal_msg(msg, proxy)}
      proxy_info[:rbuff] = part
    end

    def read_proxyd(proxyd)
      check_expire_proxies

      begin
        proxy, addrinfo = proxyd.accept_nonblock
      rescue Exception => e
        puts "accept a proxy #{e.class}"
        return
      end

      puts "accept a proxy #{addrinfo.ip_unpack.inspect}"

      @proxy_infos[proxy] = {
        addrinfo: addrinfo,
        im: nil,
        rbuff: '',
        wbuff: ''
      }
      add_read(proxy, :proxy)
    end

    def resolve_domain_port(domain_port, src_id)
      return if domain_port.nil? || domain_port.empty?
      colon_idx = domain_port.rindex(':')
      return unless colon_idx
      src_info = @src_infos[src_id]
      return unless src_info
      im = src_info[:im]

      domain = domain_port[0...colon_idx]
      port = domain_port[(colon_idx + 1)..-1].to_i

      if (domain !~ /^(?=^.{3,255}$)[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$/) || (domain =~ /^((0\.\d{1,3}\.\d{1,3}\.\d{1,3})|(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(127\.\d{1,3}\.\d{1,3}\.\d{1,3})|(169\.254\.\d{1,3}\.\d{1,3})|(172\.((1[6-9])|(2\d)|(3[01]))\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3})|(255\.255\.255\.255)|(localhost))$/)
        # 忽略非法域名，内网地址
        puts "ignore #{domain}"
        return
      end

      if domain =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}$/
        # ipv4
        new_a_dst(domain, domain, port, src_id)
        return
      end

      ip, created_at = @resolv_caches[domain]

      if ip
        if Time.new - created_at < @expire_resolv_cache
          new_a_dst(domain, ip, port, src_id)
          return
        end

        @resolv_caches.delete(domain)
      end

      begin
        data = pack_a_query(domain)
      rescue Exception => e
        puts "dns pack a query #{e.class} #{e.message} #{domain}" if @is_debug
        return
      end

      check_expire_dnses
      dns = Socket.new(Socket::AF_INET, Socket::SOCK_DGRAM, 0)

      begin
        @nameserver_addrs.each{|addr| dns.sendmsg(data, 0, addr)}
      rescue Exception => e
        puts "dns send data #{e.class} #{domain}"
        dns.close
        return
      end

      @dns_infos[dns] = {
        domain: domain,
        im: im,
        port: port,
        src_id: src_id
      }
      add_read(dns, :dns)
    end

    def send_data(sock, data, target_addr)
      begin
        sock.sendmsg(data, 0, target_addr)
      rescue Exception => e
        puts "sendmsg #{e.class}"
      end
    end

    def set_dst_closing(dst)
      return if dst.nil? || dst.closed?
      dst_info = @dst_infos[dst]
      return if dst_info.nil? || dst_info[:closing]
      dst_info[:closing] = true
      add_write(dst)
    end

    def set_p2_closing(p2)
      return if p2.nil? || p2.closed?
      p2_info = @p2_infos[p2]
      return if p2_info.nil? || p2_info[:closing]
      p2_info[:closing] = true
      add_write(p2)
    end

    def set_update(sock)
      @updates[sock] = Time.new

      if @updates_limit - @updates.size <= 20
        puts "updates #{@updates.size}"
      end

      if @updates.size >= @updates_limit
        puts "eliminate updates"

        @updates.keys.each do |_sock|
          case @roles[_sock]
          when :big
            close_big(_sock)
          when :dns
            close_dns(_sock)
          when :dst
            close_dst(_sock)
          when :mem
            close_mem(_sock)
          when :p2
            close_p2(_sock)
          when :proxy
            close_proxy(_sock)
          when :rsv
            close_rsv(_sock)
          else
            close_sock(_sock)
          end
        end

        @eliminate_count += 1
      end
    end

    def write_big(big)
      big_info = @big_infos[big]

      unless big_info
        puts "big info not found delete big"
        @writes.delete(big)
        return
      end

      im = big_info[:im]
      im_info = @im_infos[im]

      if im_info.nil? || im_info[:proxy].nil?
        puts "proxy not found close big"
        close_big(big)
        return
      end

      return if @writes.include?(im_info[:proxy])
      data = big_info[:wbuff]

      if data.empty?
        @writes.delete(big)
        return
      end

      begin
        written = big.write_nonblock(data)
      rescue Errno::EINPROGRESS
        return
      rescue Exception => e
        close_big(big)
        return
      end

      set_update(big)
      im_info[:out] += written
      data = data[written..-1]
      big_info[:wbuff] = data

      if big_info[:wbuff].empty? && big_info[:overflowing]
        puts "big empty #{big_info[:im]}"
        big_info[:overflowing] = false

        @dst_infos.select{|_, info| (info[:im] == im) && info[:is_big]}.each do |dst, info|
          puts "resume dst #{info[:src_id]} #{info[:domain]}"
          add_read(dst)
        end

        @p2_infos.select{|_, info| (info[:im] == im) && info[:is_big]}.each do |p2, info|
          puts "resume p2 #{info[:p2_id]}"
          add_read(p2)
        end
      end
    end

    def write_dst(dst)
      dst_info = @dst_infos[dst]

      unless dst_info
        puts "dst info not found delete dst"
        @writes.delete(dst)
        return
      end

      dst_info[:connected] = true
      data = dst_info[:wbuff]

      if data.empty?
        if dst_info[:closing]
          close_dst(dst)
        else
          @writes.delete(dst)
        end

        return
      end

      begin
        written = dst.write_nonblock(data)
      rescue Errno::EINPROGRESS
        return
      rescue Exception => e
        close_dst(dst)
        return
      end

      set_update(dst)
      im = dst_info[:im]
      im_info = @im_infos[im]

      if im_info
        im_info[:out] += written
        big = im_info[:big]
      end
      
      data = data[written..-1]
      dst_info[:wbuff] = data
      src_id = dst_info[:src_id]
      domain = dst_info[:domain]

      if dst_info[:overflowing] && dst_info[:wbuff].empty? && dst_info[:wpend].empty?
        puts "dst empty #{im} #{src_id} #{domain}"
        dst_info[:overflowing] = false

        if big
          puts "resume big"
          add_read(big)
        end
      end
    end

    def write_mem(mem)
      mem_info = @mem_infos[mem]

      unless mem_info
        puts "mem info not found delete mem"
        @writes.delete(mem)
        return
      end
      
      data = mem_info[:wbuff]

      if data.empty?
        @writes.delete(mem)
        close_mem(mem)
        return
      end

      begin
        written = mem.write_nonblock(data)
      rescue Errno::EINPROGRESS
        return
      rescue Exception => e
        close_mem(mem)
        return
      end

      set_update(mem)
      data = data[written..-1]
      mem_info[:wbuff] = data
    end

    def write_p2(p2)
      p2_info = @p2_infos[p2]

      unless p2_info
        puts "p2 info not found delete p2"
        @writes.delete(p2)
        return
      end

      data = p2_info[:wbuff]

      if data.empty?
        if p2_info[:closing]
          close_p2(p2)
        else
          @writes.delete(p2)
        end

        return
      end

      begin
        written = p2.write_nonblock(data)
      rescue Errno::EINPROGRESS
        return
      rescue Exception => e
        close_p2(p2)
        return
      end

      set_update(p2)
      im = p2_info[:im]
      im_info = @im_infos[im]
      big = im_info[:big] if im_info
      data = data[written..-1]
      p2_info[:wbuff] = data
      p2_id = p2_info[:p2_id]

      if p2_info[:overflowing] && p2_info[:wbuff].empty? && p2_info[:wpend].empty?
        puts "p2 empty #{im} #{p2_id}"
        p2_info[:overflowing] = false

        if big
          puts "resume big"
          add_read(big)
        end
      end
    end

    def write_proxy(proxy)
      proxy_info = @proxy_infos[proxy]

      unless proxy_info
        puts "proxy info not found delete proxy"
        @writes.delete(proxy)
        return
      end

      data = proxy_info[:wbuff]

      if data.empty?
        @writes.delete(proxy)
        return
      end

      begin
        written = proxy.write_nonblock(data)
      rescue Errno::EINPROGRESS
        return
      rescue Exception => e
        close_proxy(proxy)
        return
      end

      set_update(proxy)
      im = proxy_info[:im]
      im_info = @im_infos[im]
      im_info[:out] += written if im_info
      data = data[written..-1]
      proxy_info[:wbuff] = data
    end

  end
end
