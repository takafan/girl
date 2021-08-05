module Girl
  class ProxydWorker

    ##
    # initialize
    #
    def initialize( proxyd_port, infod_port, nameserver )
      @custom = Girl::ProxydCustom.new
      @reads = []
      @writes = []
      @roles = {}                      # sock => :dotr / :ctld / :ctl / :infod / :dst / :atund / :btund / :atun / :btun / :dns
      @ctl_infos = {}                  # im => { :ctl_addr, :ctld, :atunds, :btunds }
      @atund_infos = {}                # atund => { :im }
      @btund_infos = {}                # btund => { :im }
      @resolv_caches = {}              # domain => [ ip, created_at ]
      @dst_infos = ConcurrentHash.new  # dst => { :dst_id, :im, :domain, :connected, :rbuff, :atun, :btun, :wbuff, :src_id,
                                       #          :created_at, :last_recv_at, :last_sent_at, :closing_write, :closing, :paused }
      @atun_infos = ConcurrentHash.new # atun => { :im, :dst, :domain, :rbuff, :paused }
      @btun_infos = ConcurrentHash.new # btun => { :im, :dst, :domain, :wbuff, :closing }
      @dns_infos = ConcurrentHash.new  # dns => { :im, :src_id, :domain, :port, :created_at, :closing }
      @traffs = ConcurrentHash.new     # im => { :in, :out }
      @nameserver_addr = Socket.sockaddr_in( 53, nameserver )

      new_a_pipe
      new_ctlds( proxyd_port )
      new_a_infod( infod_port )
    end

    ##
    # looping
    #
    def looping
      puts "#{ Time.new } looping"
      loop_check_state
      loop_check_traff

      loop do
        rs, ws = IO.select( @reads, @writes )

        rs.each do | sock |
          role = @roles[ sock ]

          case role
          when :dotr then
            read_dotr( sock )
          when :dns then
            read_dns( sock )
          when :ctld then
            read_ctld( sock )
          when :infod then
            read_infod( sock )
          when :dst then
            read_dst( sock )
          when :atund then
            read_atund( sock )
          when :btund then
            read_btund( sock )
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
          when :dst then
            write_dst( sock )
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
      exit
    end

    private

    ##
    # add btun wbuff
    #
    def add_btun_wbuff( btun, data )
      return if btun.nil? || btun.closed?
      btun_info = @btun_infos[ btun ]
      return if btun_info[ :closing ]
      btun_info[ :wbuff ] << data
      add_write( btun )

      if btun_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        dst = btun_info[ :dst ]

        if dst then
          dst_info = @dst_infos[ dst ]

          if dst_info then
            puts "#{ Time.new } pause dst #{ dst_info[ :im ].inspect } #{ dst_info[ :domain ].inspect }"
            @reads.delete( dst )
            dst_info[ :paused ] = true
          end
        end
      end
    end

    ##
    # add dst rbuff
    #
    def add_dst_rbuff( dst, data )
      return if dst.nil? || dst.closed?
      dst_info = @dst_infos[ dst ]
      return if dst_info[ :closing ]
      dst_info[ :rbuff ] << data

      if dst_info[ :rbuff ].bytesize >= WBUFF_LIMIT then
        puts "#{ Time.new } dst rbuff full"
        close_dst( dst )
      end
    end

    ##
    # add dst wbuff
    #
    def add_dst_wbuff( dst, data )
      return if dst.nil? || dst.closed?
      dst_info = @dst_infos[ dst ]
      return if dst_info[ :closing ]
      dst_info[ :wbuff ] << data
      dst_info[ :last_recv_at ] = Time.new
      add_write( dst )

      if dst_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        atun = dst_info[ :atun ]

        if atun then
          atun_info = @atun_infos[ atun ]

          if atun_info then
            puts "#{ Time.new } pause atun #{ atun_info[ :im ].inspect } #{ atun_info[ :domain ].inspect }"
            @reads.delete( atun )
            atun_info[ :paused ] = true
          end
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
    end

    ##
    # add write
    #
    def add_write( sock )
      return if sock.nil? || sock.closed? || @writes.include?( sock )
      @writes << sock
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
    # close atund
    #
    def close_atund( atund )
      return if atund.nil? || atund.closed?
      # puts "debug close atund"
      close_sock( atund )
      @atund_infos.delete( atund )
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
    # close btund
    #
    def close_btund( btund )
      return if btund.nil? || btund.closed?
      # puts "debug close btund"
      close_sock( btund )
      @btund_infos.delete( btund )
    end

    ##
    # close dns
    #
    def close_dns( dns )
      return if dns.nil? || dns.closed?
      close_sock( dns )
      @dns_infos.delete( dns )
    end

    ##
    # close dsts
    #
    def close_dsts( im )
      @dst_infos.select{ | _, info | info[ :im ] == im }.keys.each{ | dst | close_dst( dst ) }
    end

    ##
    # close dst
    #
    def close_dst( dst )
      return if dst.nil? || dst.closed?
      # puts "debug close dst"
      close_sock( dst )
      dst_info = @dst_infos.delete( dst )

      if dst_info then
        close_atun( dst_info[ :atun ] )
        close_btun( dst_info[ :btun ] )
      end
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
    # loop check state
    #
    def loop_check_state
      Thread.new do
        loop do
          sleep CHECK_STATE_INTERVAL
          now = Time.new

          @dst_infos.select{ | dst, _ | !dst.closed? }.each do | dst, dst_info |
            if dst_info[ :connected ] then
              last_recv_at = dst_info[ :last_recv_at ] || dst_info[ :created_at ]
              last_sent_at = dst_info[ :last_sent_at ] || dst_info[ :created_at ]
              is_expire = ( now - last_recv_at >= EXPIRE_AFTER ) && ( now - last_sent_at >= EXPIRE_AFTER )
            else
              is_expire = ( now - dst_info[ :created_at ] >= EXPIRE_CONNECTING )
            end

            if is_expire then
              puts "#{ Time.new } expire dst #{ dst_info[ :im ].inspect } #{ dst_info[ :domain ].inspect }"
              dst_info[ :closing ] = true
              next_tick
            elsif dst_info[ :paused ] then
              btun = dst_info[ :btun ]

              if btun && !btun.closed? then
                btun_info = @btun_infos[ btun ]

                if btun_info[ :wbuff ].bytesize < RESUME_BELOW then
                  puts "#{ Time.new } resume dst #{ dst_info[ :im ].inspect } #{ dst_info[ :domain ].inspect }"
                  add_read( dst )
                  dst_info[ :paused ] = false
                  next_tick
                end
              end
            end
          end

          @atun_infos.select{ | atun, info | !atun.closed? && info[ :paused ] }.each do | atun, atun_info |
            dst = atun_info[ :dst ]

            if dst && !dst.closed? then
              dst_info = @dst_infos[ dst ]

              if dst_info[ :wbuff ].bytesize < RESUME_BELOW then
                puts "#{ Time.new } resume atun #{ atun_info[ :im ].inspect } #{ atun_info[ :domain ].inspect }"
                add_read( atun )
                atun_info[ :paused ] = false
                next_tick
              end
            end
          end

          @dns_infos.select{ | dns, info | !dns.closed? && ( now - info[ :created_at ] >= EXPIRE_NEW ) }.values.each do | dns_info |
            puts "#{ Time.new } expire dns #{ dns_info[ :im ].inspect } #{ dns_info[ :domain ].inspect }"
            dns_info[ :closing ] = true
            next_tick
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

            if Time.new.day == RESET_TRAFF_DAY then
              puts "#{ Time.new } reset traffs"
              @traffs.each{ | im, info | info[ :in ] = info[ :out ] = 0 }
            end
          end
        end
      end
    end

    ##
    # new a dst
    #
    def new_a_dst( ipaddr, domain, port, src_id, im, ctld, ctl_addr )
      return if ctld.nil? || ctld.closed?

      begin
        dst = Socket.new( ipaddr.ipv4? ? Socket::AF_INET : Socket::AF_INET6, Socket::SOCK_STREAM, 0 )
      rescue Exception => e
        puts "#{ Time.new } new a dst #{ im.inspect } #{ domain.inspect } #{ port } #{ e.class }"
        return
      end

      dst.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
      ip = ipaddr.to_s
      destination_addr = Socket.sockaddr_in( port, ip )

      begin
        dst.connect_nonblock( destination_addr )
      rescue IO::WaitWritable
      rescue Exception => e
        puts "#{ Time.new } connect destination #{ im.inspect } #{ domain.inspect } #{ ip } #{ port } #{ e.class }"
        dst.close
        return
      end

      dst_id = dst.local_address.ip_port

      @dst_infos[ dst ] = {
        dst_id: dst_id,       # dst_id
        im: im,               # 标识
        domain: domain,       # 目的地
        connected: false,     # 是否已连接
        rbuff: '',            # 对应的tun没准备好，暂存读到的流量
        atun: nil,            # 对应的atun
        btun: nil,            # 对应的btun
        wbuff: '',            # 从tun读到的流量
        src_id: src_id,       # 近端src id
        created_at: Time.new, # 创建时间
        last_recv_at: nil,    # 上一次收到新流量（由tun收到）的时间
        last_sent_at: nil,    # 上一次发出流量（由tun发出）的时间
        closing_write: false, # 准备关闭写
        closing: false,       # 准备关闭
        paused: false         # 已暂停
      }

      add_read( dst, :dst )
      add_write( dst )

      data = [ PAIRED, src_id, dst_id ].pack( 'CQ>n' )
      # puts "debug add ctlmsg paired #{ im.inspect } #{ src_id } #{ dst_id }"
      send_ctlmsg( ctld, data, ctl_addr )
    end

    ##
    # new a infod
    #
    def new_a_infod( infod_port )
      infod = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      infod.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      infod.bind( Socket.sockaddr_in( infod_port, '127.0.0.1' ) )
      puts "#{ Time.new } infod bind on #{ infod_port }"
      add_read( infod, :infod )
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
    # new a tund
    #
    def new_a_tund
      tund = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      tund.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
      tund.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )
      tund.listen( 127 )
      tund
    end

    ##
    # new ctlds
    #
    def new_ctlds( begin_port )
      10.times do | i |
        ctld_port = begin_port + i
        ctld = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
        ctld.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
        ctld.bind( Socket.sockaddr_in( ctld_port, '0.0.0.0' ) )
        puts "#{ Time.new } ctld bind on #{ ctld_port }"
        add_read( ctld, :ctld )
      end
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
    # resolve domain port
    #
    def resolve_domain_port( domain_port, src_id, im, ctld, ctl_addr )
      colon_idx = domain_port.rindex( ':' )
      return unless colon_idx

      domain = domain_port[ 0...colon_idx ]
      port = domain_port[ ( colon_idx + 1 )..-1 ].to_i
      resolv_cache = @resolv_caches[ domain ]

      if resolv_cache then
        ipaddr, created_at = resolv_cache

        if Time.new - created_at < RESOLV_CACHE_EXPIRE then
          # puts "debug #{ domain.inspect } hit resolv cache #{ ipaddr.to_s }"
          new_a_dst( ipaddr, domain, port, src_id, im, ctld, ctl_addr )
          return
        end

        # puts "debug expire #{ domain.inspect } resolv cache"
        @resolv_caches.delete( domain )
      end

      begin
        ipaddr = IPAddr.new( domain )

        if ipaddr.ipv4? || ipaddr.ipv6? then
          new_a_dst( ipaddr, domain, port, src_id, im, ctld, ctl_addr )
          return
        end
      rescue Exception => e
      end

      begin
        packet = Net::DNS::Packet.new( domain )
      rescue Exception => e
        puts "#{ Time.new } new packet #{ e.class } #{ im.inspect } #{ domain.inspect }"
        return
      end

      dns = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )

      begin
        # puts "debug dns query #{ domain.inspect }"
        dns.sendmsg_nonblock( packet.data, 0, @nameserver_addr )
      rescue Exception => e
        puts "#{ Time.new } dns sendmsg #{ e.class } #{ im.inspect } #{ domain.inspect }"
        dns.close
        return
      end

      @dns_infos[ dns ] = {
        im: im,
        src_id: src_id,
        domain: domain,
        port: port,
        created_at: Time.new,
        closing: false
      }

      add_read( dns, :dns )
    end

    ##
    # send ctlmsg
    #
    def send_ctlmsg( ctld, data, to_addr )
      return if ctld.nil? || ctld.closed?
      data = @custom.encode( data )

      begin
        ctld.sendmsg_nonblock( data, 0, to_addr )
      rescue Exception => e
        puts "#{ Time.new } ctld sendmsg #{ e.class }"
      end
    end

    ##
    # send tund port
    #
    def send_tund_port( ctl_info )
      atund_port = ctl_info[ :atunds ].sample.local_address.ip_port
      btund_port = ctl_info[ :btunds ].sample.local_address.ip_port
      puts "#{ Time.new } send tund port #{ atund_port } #{ btund_port }"
      data = [ TUND_PORT, atund_port, btund_port ].pack( 'Cnn' )
      send_ctlmsg( ctl_info[ :ctld ], data, ctl_info[ :ctl_addr ] )
    end

    ##
    # set btun closing
    #
    def set_btun_closing( btun )
      return if btun.nil? || btun.closed?
      btun_info = @btun_infos[ btun ]
      return if btun_info[ :closing ]
      # puts "debug set btun closing"
      btun_info[ :closing ] = true
      add_write( btun )
    end

    ##
    # set dst closing write
    #
    def set_dst_closing_write( dst )
      return if dst.nil? || dst.closed?
      dst_info = @dst_infos[ dst ]
      return if dst_info[ :closing ] || dst_info[ :closing_write ]
      # puts "debug set dst closing write"
      dst_info[ :closing_write ] = true
      add_write( dst )
    end

    ##
    # read dotr
    #
    def read_dotr( dotr )
      dotr.read_nonblock( READ_SIZE )
      @dns_infos.select{ | _, info | info[ :closing ] }.keys.each{ | dns | close_dns( dns ) }
      @dst_infos.select{ | _, info | info[ :closing ] }.keys.each{ | dst | close_dst( dst ) }
    end

    ##
    # read dns
    #
    def read_dns( dns )
      if dns.closed? then
        puts "#{ Time.new } read dns but dns closed?"
        return
      end

      begin
        data, addrinfo, rflags, *controls = dns.recvmsg
      rescue Exception => e
        puts "#{ Time.new } dns recvmsg #{ e.class }"
        close_dns( dns )
        return
      end

      # puts "debug recv dns #{ data.inspect }"
      dns_info = @dns_infos[ dns ]
      im = dns_info[ :im ]
      ctl_info = @ctl_infos[ im ]

      unless ctl_info then
        puts "#{ Time.new } read dns but ctl already closed #{ im.inspect }"
        close_dns( dns )
        return
      end

      begin
        packet = Net::DNS::Packet::parse( data )
      rescue Exception => e
        puts "#{ Time.new } parse packet #{ e.class }"
        close_dns( dns )
        return
      end

      ans = packet.answer.find{ | ans | ans.class == Net::DNS::RR::A }

      if ans then
        domain = dns_info[ :domain ]
        ipaddr = IPAddr.new( ans.value )
        @resolv_caches[ domain ] = [ ipaddr, Time.new ]
        src_id = dns_info[ :src_id ]
        port = dns_info[ :port ]
        new_a_dst( ipaddr, domain, port, src_id, im, ctl_info[ :ctld ], ctl_info[ :ctl_addr ] )
      end

      close_dns( dns )
    end

    ##
    # read ctld
    #
    def read_ctld( ctld )
      data, addrinfo, rflags, *controls = ctld.recvmsg
      data = @custom.decode( data )
      ctl_num = data[ 0 ].unpack( 'C' ).first
      ctl_addr = addrinfo.to_sockaddr

      case ctl_num
      when HELLO then
        return if data.bytesize <= 1
        im = data[ 1..-1 ]
        result = @custom.check( im, addrinfo )

        if result != :success then
          puts "#{ Time.new } #{ result } #{ im.inspect } #{ addrinfo.inspect }"
          return
        end

        unless @traffs.include?( im ) then
          @traffs[ im ] = {
            in: 0,
            out: 0
          }
        end

        ctl_info = @ctl_infos[ im ]

        if ctl_info then
          ctl_info[ :ctl_addr ] = ctl_addr
          ctl_info[ :ctld ] = ctld
        else
          atunds = []
          btunds = []

          10.times do
            atund = new_a_tund
            btund = new_a_tund
            @atund_infos[ atund ] = { im: im }
            @btund_infos[ btund ] = { im: im }
            add_read( atund, :atund )
            add_read( btund, :btund )
            atunds << atund
            btunds << btund
          end

          ctl_info = {
            ctl_addr: ctl_addr, # ctl地址
            ctld: ctld,         # 对应的ctld
            atunds: atunds,     # 对应atunds
            btunds: btunds      # 对应btunds
          }

          @ctl_infos[ im ] = ctl_info
        end

        puts "#{ Time.new } got hello #{ addrinfo.ip_unpack.inspect } #{ im.inspect }"
        print "ctls #{ @ctl_infos.size } atunds #{ @atund_infos.size } btunds #{ @btund_infos.size }"
        puts " dsts #{ @dst_infos.size } atuns #{ @atun_infos.size } btuns #{ @btun_infos.size } dnses #{ @dns_infos.size }"
        send_tund_port( ctl_info )
      when A_NEW_SOURCE then
        return if data.bytesize <= 9
        src_id = data[ 1, 8 ].unpack( 'Q>' ).first
        domain_port, im = data[ 9..-1 ].split( '/' )

        if im then
          ctl_info = @ctl_infos[ im ]

          unless ctl_info then
            puts "#{ Time.new } got a new source but unknown im #{ im.inspect }"
            send_ctlmsg( ctld, [ UNKNOWN_CTL_ADDR ].pack( 'C' ), ctl_addr )
            return
          end

          ctl_info[ :ctl_addr ] = ctl_addr
        else
          im, ctl_info = @ctl_infos.find{ | _, info | info[ :ctl_addr ] == ctl_addr }

          unless im then
            puts "#{ Time.new } got a new source but unknown ctl addr"
            send_ctlmsg( ctld, [ UNKNOWN_CTL_ADDR ].pack( 'C' ), ctl_addr )
            return
          end
        end

        ctl_info[ :ctld ] = ctld
        dst_info = @dst_infos.values.find{ | info | info[ :src_id ] == src_id }

        if dst_info then
          # puts "debug dst info exist, send ctlmsg paired #{ src_id } #{ dst_info[ :dst_id ] }"
          data2 = [ PAIRED, src_id, dst_info[ :dst_id ] ].pack( 'CQ>n' )
          send_ctlmsg( ctld, data2, ctl_addr )
          return
        end

        # puts "debug got a new source #{ src_id } #{ domain_port.inspect } #{ im.inspect }"
        resolve_domain_port( domain_port, src_id, im, ctl_info[ :ctld ], ctl_info[ :ctl_addr ] )
      when CTL_FIN then
        im, _ = @ctl_infos.find{ | _, info | info[ :ctl_addr ] == ctl_addr }
        return unless im
        # puts "debug got ctl fin #{ im.inspect }"
        close_dsts( im )
        ctl_info = @ctl_infos.delete( im )
        ctl_info[ :atunds ].each{ | atund | close_atund( atund ) }
        ctl_info[ :btunds ].each{ | btund | close_btund( btund ) }
      when SOURCE_CLOSED then
        return if data.bytesize <= 9
        src_id = data[ 1, 8 ].unpack( 'Q>' ).first
        im = data[ 9..-1 ]
        return unless @ctl_infos.include?( im )
        # puts "debug got src closed #{ src_id } #{ im.inspect }"
        dst, _ = @dst_infos.find{ | _, info | info[ :src_id ] == src_id }
        close_dst( dst )
      when SOURCE_CLOSED_READ then
        return if data.bytesize <= 9
        src_id = data[ 1, 8 ].unpack( 'Q>' ).first
        im = data[ 9..-1 ]
        return unless @ctl_infos.include?( im )
        # puts "debug got src closed read #{ src_id } #{ im.inspect }"
        dst, _ = @dst_infos.find{ | _, info | info[ :src_id ] == src_id }
        set_dst_closing_write( dst )
      when SOURCE_CLOSED_WRITE then
        return if data.bytesize <= 9
        src_id = data[ 1, 8 ].unpack( 'Q>' ).first
        im = data[ 9..-1 ]
        return unless @ctl_infos.include?( im )
        # puts "debug got src closed write #{ src_id } #{ im.inspect }"
        dst, _ = @dst_infos.find{ | _, info | info[ :src_id ] == src_id }
        close_read_dst( dst )
      end
    end

    ##
    # read infod
    #
    def read_infod( infod )
      data, addrinfo, rflags, *controls = infod.recvmsg
      ctl_num = data[ 0 ].unpack( 'C' ).first
      # puts "debug infod got #{ ctl_num } #{ addrinfo.ip_unpack.inspect }"

      case ctl_num
      when TRAFF_INFOS then
        data2 = [ TRAFF_INFOS ].pack( 'C' )

        @traffs.sort.each do | im, info |
          data2 << [ [ im.bytesize ].pack( 'C' ), im, [ info[ :in ], info[ :out ] ].pack( 'Q>Q>' ) ].join
        end

        begin
          infod.sendmsg_nonblock( data2, 0, addrinfo )
        rescue Exception => e
          puts "#{ Time.new } infod sendmsg to #{ e.class } #{ addrinfo.ip_unpack.inspect }"
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
      btun = dst_info[ :btun ]

      begin
        data = dst.read_nonblock( CHUNK_SIZE )
      rescue Exception => e
        # puts "debug read dst #{ e.class }"
        close_read_dst( dst )
        set_btun_closing( btun )
        return
      end

      @traffs[ dst_info[ :im ] ][ :in ] += data.bytesize

      if btun then
        add_btun_wbuff( btun, pack_a_chunk( data ) )
      else
        # puts "debug add dst.rbuff #{ data.bytesize }"
        add_dst_rbuff( dst, data )
      end
    end

    ##
    # read atund
    #
    def read_atund( atund )
      if atund.closed? then
        puts "#{ Time.new } read atund but atund closed?"
        return
      end

      atund_info = @atund_infos[ atund ]

      begin
        atun, _ = atund.accept_nonblock
      rescue Exception => e
        puts "#{ Time.new } atund accept #{ e.class } #{ atund_info[ :im ].inspect }"
        close_dsts( atund_info[ :im ] )
        return
      end

      # puts "debug accept a atun"

      @atun_infos[ atun ] = {
        im: atund_info[ :im ], # 标识
        dst: nil,              # 对应dst
        domain: nil,           # 目的地
        rbuff: '',             # 暂存不满一块的流量
        paused: false          # 是否暂停
      }

      add_read( atun, :atun )
    end

    ##
    # read btund
    #
    def read_btund( btund )
      if btund.closed? then
        puts "#{ Time.new } read btund but btund closed?"
        return
      end

      btund_info = @btund_infos[ btund ]

      begin
        btun, _ = btund.accept_nonblock
      rescue Exception => e
        puts "#{ Time.new } btund accept #{ e.class } #{ btund_info[ :im ].inspect }"
        close_dsts( btund_info[ :im ] )
        return
      end

      # puts "debug accept a btun"

      @btun_infos[ btun ] = {
        im: btund_info[ :im ],             # 标识
        dst: nil,                          # 对应dst
        domain: nil,                       # 目的地
        wbuff: '',                         # 写前
        closing: false                     # 准备关闭
      }

      add_read( btun, :btun )
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
      dst = atun_info[ :dst ]

      begin
        data = atun.read_nonblock( READ_SIZE )
      rescue Exception => e
        # puts "debug read atun #{ e.class }"
        close_atun( atun )
        return
      end

      unless dst then
        if data.bytesize < 2 then
          # puts "debug unexpect data length? #{ data.bytesize }"
          close_atun( atun )
          return
        end

        dst_id = data[ 0, 2 ].unpack( 'n' ).first
        dst, dst_info = @dst_infos.find{ | _, info | info[ :dst_id ] == dst_id }

        unless dst then
          # puts "debug dst not found #{ dst_id }"
          close_atun( atun )
          return
        end

        # puts "debug set atun.dst #{ dst_id }"
        atun_info[ :dst ] = dst
        atun_info[ :domain ] = dst_info[ :domain ]
        dst_info[ :atun ] = atun
        data = data[ 2..-1 ]
      end

      data = "#{ atun_info[ :rbuff ] }#{ data }"

      loop do
        if data.bytesize <= 2 then
          atun_info[ :rbuff ] = data
          break
        end

        len = data[ 0, 2 ].unpack( 'n' ).first

        if len == 0 then
          puts "#{ Time.new } zero traffic len?"
          close_atun( atun )
          close_dst( dst )
          return
        end

        chunk = data[ 2, len ]

        if chunk.bytesize < len then
          atun_info[ :rbuff ] = data
          break
        end

        chunk = @custom.decode( chunk )
        add_dst_wbuff( dst, chunk )
        data = data[ ( 2 + len )..-1 ]
      end
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

      begin
        data = btun.read_nonblock( READ_SIZE )
      rescue Exception => e
        # puts "debug read btun #{ e.class }"
        close_btun( btun )
        return
      end

      if data.bytesize != 2 then
        close_btun( btun )
        return
      end

      @traffs[ btun_info[ :im ] ][ :in ] += data.bytesize
      dst = btun_info[ :dst ]

      if dst then
        # puts "debug unexpect data?"
        close_btun( btun )
        return
      end

      dst_id = data.unpack( 'n' ).first
      dst, dst_info = @dst_infos.find{ | _, info | info[ :dst_id ] == dst_id }

      unless dst then
        # puts "debug dst #{ dst_id } not found"
        close_btun( btun )
        return
      end

      # puts "debug set btun.dst #{ dst_id }"
      btun_info[ :dst ] = dst
      btun_info[ :domain ] = dst_info[ :domain ]

      unless dst_info[ :rbuff ].empty? then
        data2 = ''

        until dst_info[ :rbuff ].empty? do
          _data = dst_info[ :rbuff ][ 0, CHUNK_SIZE ]
          data_size = _data.bytesize
          # puts "debug move dst.rbuff to btun.wbuff"
          data2 << pack_a_chunk( _data )
          dst_info[ :rbuff ] = dst_info[ :rbuff ][ data_size..-1 ]
        end

        add_btun_wbuff( btun, data2 )
      end

      dst_info[ :btun ] = btun
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
      dst_info[ :connected ] = true
      atun = dst_info[ :atun ]
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
      rescue Exception => e
        # puts "debug write dst #{ e.class }"
        close_write_dst( dst )
        close_atun( atun )
        return
      end

      data = data[ written..-1 ]
      dst_info[ :wbuff ] = data
      @traffs[ dst_info[ :im ] ][ :out ] += written
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
      dst = btun_info[ :dst ]
      data = btun_info[ :wbuff ]

      # 写前为空，处理关闭写
      if data.empty? then
        if btun_info[ :closing ] then
          close_btun( btun )
        else
          @writes.delete( btun )
        end

        return
      end

      # 写入
      begin
        written = btun.write_nonblock( data )
      rescue Exception => e
        # puts "debug write btun #{ e.class }"
        close_btun( btun )
        close_read_dst( dst )
        return
      end

      data = data[ written..-1 ]
      btun_info[ :wbuff ] = data
      @traffs[ btun_info[ :im ] ][ :out ] += written

      if dst && !dst.closed? then
        dst_info = @dst_infos[ dst ]
        dst_info[ :last_sent_at ] = Time.new
      end
    end

  end
end
