module Girl
  class ProxydWorker

    ##
    # initialize
    #
    def initialize( proxyd_port )
      @custom = Girl::ProxydCustom.new
      @mutex = Mutex.new
      @reads = []
      @writes = []
      @roles = {}           # sock => :dotr / :proxyd / :dst / :tund
      @dst_infos = {}       # dst => {}
      @tund_infos = {}      # tund => {}
      @tunneling_tunds = {} # tunneling_addr => tund
      @resolv_caches = {}   # domain => [ ip, created_at ]

      dotr, dotw = IO.pipe
      @dotw = dotw
      add_read( dotr, :dotr )
      new_a_proxyd( proxyd_port )
    end

    ##
    # looping
    #
    def looping
      puts "p#{ Process.pid } #{ Time.new } looping"
      loop_check_expire
      loop_check_status

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
            when :dst then
              read_dst( sock )
            when :tund then
              read_tund( sock )
            end
          end

          ws.each do | sock |
            case @roles[ sock ]
            when :proxyd then
              write_proxyd( sock )
            when :dst then
              write_dst( sock )
            when :tund then
              write_tund( sock )
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
    # send miss or continue
    #
    def send_miss_or_continue( tund, src_id, biggest_src_pack_id )
      now = Time.new
      tund_info = @tund_infos[ tund ]
      dst_id = tund_info[ :dst_ids ][ src_id ]

      if dst_id then
        dst = tund_info[ :dsts ][ dst_id ]

        if dst then
          dst_info = @dst_infos[ dst ]
          continue_recv_pack_id = dst_info[ :continue_recv_pack_id ]

          if dst_info[ :continue_recv_pack_id ] < biggest_src_pack_id then
            # 有跳号包，发miss（single miss和range miss）。
            singles = []
            ranges = []
            begin_miss_pack_id = continue_recv_pack_id + 1

            dst_info[ :pieces ].keys.sort.each do | pack_id |
              if begin_miss_pack_id < pack_id then
                end_miss_pack_id = pack_id - 1

                if begin_miss_pack_id == end_miss_pack_id then
                  singles << begin_miss_pack_id
                else
                  # ranges << [ begin_miss_pack_id, end_miss_pack_id ]
                  singles += ( begin_miss_pack_id..end_miss_pack_id ).to_a
                end
              end

              begin_miss_pack_id = pack_id + 1
            end

            if begin_miss_pack_id <= biggest_src_pack_id
              # ranges << [ begin_miss_pack_id, biggest_src_pack_id ]
              singles += ( begin_miss_pack_id..biggest_src_pack_id ).to_a
            end

            if singles.any? then
              # puts "debug2 #{ now } single miss #{ singles.size }"
              # idx = 0
              #
              # while idx < singles.size do
              #   data = [ 0, SINGLE_MISS, dst_info[ :src_id ], *( singles[ idx, SINGLE_MISS_LIMIT ] ) ].pack( 'Q>CnQ>*' )
              #   add_ctlmsg( tund, data )
              #   idx += SINGLE_MISS_LIMIT
              # end

              data = [ 0, SINGLE_MISS, dst_info[ :src_id ], *( singles[ 0, SINGLE_MISS_LIMIT ] ) ].pack( 'Q>CQ>Q>*' )
              add_ctlmsg( tund, data )
            end

            # if ranges.any? then
            #   # puts "debug2 #{ now } range miss #{ ranges.size }"
            #   idx = 0
            #
            #   while idx < ranges.size do
            #     data = [ 0, RANGE_MISS, dst_info[ :src_id ], *( ranges[ idx, RANGE_MISS_LIMIT ].flatten ) ].pack( 'Q>CnQ>*' )
            #     add_ctlmsg( tund, data )
            #     idx += RANGE_MISS_LIMIT
            #   end
            #
            #   data = [ 0, RANGE_MISS, dst_info[ :src_id ], *( ranges[ idx, RANGE_MISS_LIMIT ].flatten ) ].pack( 'Q>CnQ>*' )
            #   add_ctlmsg( tund, data )
            # end
          end
        end
      end
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
              if !tund.closed? then
                last_recv_at = tund_info[ :last_recv_at ] || tund_info[ :created_at ]
                last_sent_at = tund_info[ :last_sent_at ] || tund_info[ :created_at ]

                if ( now - last_recv_at >= EXPIRE_AFTER ) && ( now - last_sent_at >= EXPIRE_AFTER ) then
                  puts "p#{ Process.pid } #{ Time.new } expire tund #{ tund_info[ :port ] }"
                  set_tund_is_closing( tund )
                  trigger = true
                end
              end
            end

            @dst_infos.each do | dst, dst_info |
              last_recv_at = dst_info[ :last_recv_at ] || dst_info[ :created_at ]
              last_sent_at = dst_info[ :last_sent_at ] || dst_info[ :created_at ]

              if ( now - last_recv_at >= EXPIRE_AFTER ) && ( now - last_sent_at >= EXPIRE_AFTER ) then
                if dst.closed? then
                  puts "p#{ Process.pid } #{ Time.new } expire dst ext #{ dst_info[ :domain_port ] }"
                  del_dst_ext( dst )
                else
                  puts "p#{ Process.pid } #{ Time.new } expire dst #{ dst_info[ :domain_port ] }"
                  set_dst_is_closing( dst )
                  trigger = true
                end
              end
            end

            if trigger then
              next_tick
            end
          end
        end
      end
    end

    ##
    # loop check status
    #
    def loop_check_status
      Thread.new do
        loop do
          sleep CHECK_STATUS_INTERVAL

          @mutex.synchronize do
            now = Time.new

            @tund_infos.each do | tund, tund_info |
              tund_info[ :dsts ].each do | _, dst |
                dst_info = @dst_infos[ dst ]

                if dst_info then
                  if dst_info[ :last_recv_at ] && ( now - dst_info[ :last_recv_at ] < 5 ) then
                    data = [ 0, IS_RESEND_READY, dst_info[ :src_id ] ].pack( 'Q>CQ>' )
                    add_ctlmsg( tund, data )
                  end

                  # 恢复读
                  if !dst_info[ :closed_read ] && dst_info[ :paused ] && ( dst_info[ :wafters ].size < RESUME_BELOW ) then
                    puts "p#{ Process.pid } #{ Time.new } resume dst #{ dst_info[ :domain_port ] }"
                    add_read( dst )
                    dst_info[ :paused ] = false
                  end
                end
              end
            end

            next_tick
          end
        end
      end
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
    # deal with destination addr
    #
    def deal_with_destination_addr( tund, src_id, destination_addr, domain_port )
      dst = Socket.new( Addrinfo.new( destination_addr ).ipv4? ? Socket::AF_INET : Socket::AF_INET6, Socket::SOCK_STREAM, 0 )
      dst.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )

      begin
        dst.connect_nonblock( destination_addr )
      rescue IO::WaitWritable
      rescue Exception => e
        puts "p#{ Process.pid } #{ Time.new } connect destination #{ e.class }"
        return false
      end

      dst_id = dst.local_address.ip_port

      @dst_infos[ dst ] = {
        id: dst_id,               # id
        tund: tund,               # 对应tund
        domain_port: domain_port, # 域名和端口
        rbuff: '',                # 读到的流量
        biggest_pack_id: 0,       # 最大包号码
        wbuff: '',                # 从tund读到的流量
        src_id: src_id,           # 近端src id
        continue_recv_pack_id: 0, # 收到的连续的最后一个包号
        pieces: {},               # 跳号包 src_pack_id => data
        fin1_src_pack_id: nil,    # 已关闭读的近端src的最终包号码
        src_fin2: false,          # 近端src是否已关闭写
        wafters: {},              # 写后 pack_id => data
        created_at: Time.new,     # 创建时间
        last_recv_at: nil,        # 上一次收到新流量（由tund收到）的时间
        last_sent_at: nil,        # 上一次发出流量（由tund发出）的时间
        paused: false,            # 是否已暂停
        closed_read: false,       # 是否已关读
        closed_write: false,      # 是否已关写
        is_closing: false         # 是否准备关闭
      }

      add_read( dst, :dst )

      tund_info = @tund_infos[ tund ]
      tund_info[ :dst_ids ][ src_id ] = dst_id
      tund_info[ :dsts ][ dst_id ] = dst

      data = [ 0, PAIRED, src_id, dst_id ].pack( 'Q>CQ>n' )
      # puts "debug1 add ctlmsg paired #{ src_id } #{ dst_id }"
      add_ctlmsg( tund, data )

      true
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
    # add proxyd ctlmsg
    #
    def add_proxyd_ctlmsg_tund_port( port, to_addr )
      data = [ 0, TUND_PORT, port ].pack( 'Q>Cn' )
      @proxyd_info[ :ctlmsgs ] << [ data, to_addr ]
      add_write( @proxyd )
    end

    ##
    # add ctlmsg resend ready
    #
    def add_ctlmsg_resend_ready( tund )
      tund_info = @tund_infos[ tund ]
      data = [ 0, RESEND_READY ].pack( 'Q>C' )
      add_ctlmsg( tund, data )
    end

    ##
    # add ctlmsg fin1
    #
    def add_ctlmsg_fin1( dst_info )
      data = [ 0, FIN1, dst_info[ :id ], dst_info[ :biggest_pack_id ] ].pack( 'Q>CnQ>' )
      add_ctlmsg( dst_info[ :tund ], data )
    end

    ##
    # add ctlmsg fin2
    #
    def add_ctlmsg_fin2( dst_info )
      data = [ 0, FIN2, dst_info[ :id ] ].pack( 'Q>Cn' )
      add_ctlmsg( dst_info[ :tund ], data )
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
    # add event dst
    #
    def add_event_dst( tund, dst )
      tund_info = @tund_infos[ tund ]

      unless tund_info[ :event_dsts ].include?( dst ) then
        tund_info[ :event_dsts ] << dst
        add_write( tund )
      end
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
    # set dst is closing
    #
    def set_dst_is_closing( dst )
      dst_info = @dst_infos[ dst ]
      dst_info[ :is_closing ] = true
      @reads.delete( dst )
      add_write( dst )
    end

    ##
    # set tund is closing
    #
    def set_tund_is_closing( tund )
      tund_info = @tund_infos[ tund ]
      tund_info[ :is_closing ] = true
      @reads.delete( tund )
      add_write( tund )
    end

    ##
    # send data
    #
    def send_data( sock, data, to_addr )
      begin
        written = sock.sendmsg_nonblock( data, 0, to_addr )
      rescue IO::WaitWritable, Errno::EINTR
        print '.'
        return :wait
      rescue Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENETDOWN => e
        return :fatal
      end

      written
    end

    ##
    # del dst ext
    #
    def del_dst_ext( dst )
      dst_info = @dst_infos.delete( dst )

      if dst_info then
        tund = dst_info[ :tund ]

        unless tund.closed? then
          tund_info = @tund_infos[ tund ]

          if tund_info then
            tund_info[ :dst_ids ].delete( dst_info[ :src_id ] )
            tund_info[ :dsts ].delete( dst_info[ :id ] )
          end
        end
      end
    end

    ##
    # close dst
    #
    def close_dst( dst )
      # puts "debug1 close dst"
      close_sock( dst )
      dst_info = @dst_infos[ dst ]

      unless dst_info[ :tund ].closed? then
        # puts "debug1 主动关dst -> 发fin1和fin2"
        add_ctlmsg_fin1( dst_info )
        add_ctlmsg_fin2( dst_info )
        del_dst_ext( dst )
      end
    end

    ##
    # close tund
    #
    def close_tund( tund )
      # puts "debug1 close tund"
      close_sock( tund )
      tund_info = @tund_infos.delete( tund )
      tund_info[ :dsts ].each{ | _, dst | set_dst_is_closing( dst ) unless dst.closed? }
      @tunneling_tunds.delete( tund_info[ :tun_addr ] )
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
    # next tick
    #
    def next_tick
      @dotw.write( '.' )
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
        puts "p#{ Process.pid } #{ Time.new } resend tund port #{ tund_info[ :port ] }"
        add_proxyd_ctlmsg_tund_port( tund_info[ :port ], from_addr )
        return
      end

      result = @custom.check( data, addrinfo )

      if result != :success then
        puts "p#{ Process.pid } #{ Time.new } #{ result }"
        return
      end

      tund = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      tund.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )
      port = tund.local_address.ip_port

      @tunneling_tunds[ from_addr ] = tund
      @tund_infos[ tund ] = {
        port: port,             # 端口
        ctlmsgs: [],            # [ ctlmsg, to_addr ]
        resend_newers: {},      # 尾巴流量重传队列 dst_id => newer_pack_ids
        resend_singles: {},     # 单个重传队列 dst_id => single_miss_pack_ids
        resend_ranges: {},      # 区间重传队列 dst_id => range_miss_pack_ids
        event_dsts: [],         # rbuff不为空，或者准备关闭的dst
        tun_addr: from_addr,    # tun地址
        dsts: {},               # dst_id => dst
        dst_ids: {},            # src_id => dst_id
        pause_dsts: [],         # 暂停的dst
        created_at: Time.new,   # 创建时间
        last_recv_at: nil,      # 上一次收到流量的时间
        last_sent_at: nil,      # 上一次发出流量的时间
        is_closing: false,      # 是否准备关闭
        changed_tun_addr: nil   # 记录到和tun addr不符的来源地址
      }

      add_read( tund, :tund )
      puts "p#{ Process.pid } #{ Time.new } a new tunnel #{ addrinfo.ip_unpack.inspect } - #{ port }, #{ @tund_infos.size } tunds"
      add_proxyd_ctlmsg_tund_port( port, from_addr )
    end

    ##
    # read dst
    #
    def read_dst( dst )
      begin
        data = dst.read_nonblock( READ_SIZE )
      rescue IO::WaitReadable, Errno::EINTR
        return
      rescue Exception => e
        # puts "debug1 read dst #{ e.class }"
        dst.close_read
        dst_info = @dst_infos[ dst ]
        dst_info[ :closed_read ] = true
        @reads.delete( dst )

        if dst_info[ :rbuff ].empty? then
          # puts "debug1 读dst -> 读到error -> 关dst读 -> rbuff空？-> 发fin1"
          add_ctlmsg_fin1( dst_info )
        end

        return
      end

      dst_info = @dst_infos[ dst ]
      dst_info[ :rbuff ] << data
      add_event_dst( dst_info[ :tund ], dst )
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
      now = Time.new
      tund_info = @tund_infos[ tund ]

      if from_addr != tund_info[ :tun_addr ] then
        # 通常是光猫刷新ip（端口也会变），但万一不是，为了避免脏数据注入，关闭tund
        puts "p#{ Process.pid } #{ Time.new } from #{ addrinfo.inspect } not match tun addr #{ Addrinfo.new( tund_info[ :tun_addr ] ).inspect }"
        tund_info[ :changed_tun_addr ] = from_addr
        set_tund_is_closing( tund )
        return
      end

      tund_info[ :last_recv_at ] = now
      pack_id = data[ 0, 8 ].unpack( 'Q>' ).first

      if pack_id == 0 then
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
        when IS_RESEND_READY then
          if tund_info[ :resend_newers ].empty? && tund_info[ :resend_singles ].empty? && tund_info[ :resend_ranges ].empty? then
            dst_id = data[ 9, 2 ].unpack( 'n' ).first
            return unless dst_id

            dst = tund_info[ :dsts ][ dst_id ]
            return unless dst

            dst_info = @dst_infos[ dst ]
            data2 = [ 0, RESEND_READY, dst_id, dst_info[ :biggest_pack_id ] ].pack( 'Q>CnQ>' )
            add_ctlmsg( tund, data2 )
          end
        when RESEND_READY then
          src_id, biggest_src_pack_id = data[ 9, 16 ].unpack( 'Q>Q>' )
          return if src_id.nil? || biggest_src_pack_id.nil?

          send_miss_or_continue( tund, src_id, biggest_src_pack_id )
        when SINGLE_MISS then
          dst_id, *miss_pack_ids = data[ 9..-1 ].unpack( 'nQ>*' )

          return if miss_pack_ids.empty?

          # puts "debug1 #{ now } got single miss #{ miss_pack_ids[ 0, 100 ].inspect }"

          if tund_info[ :resend_singles ].include?( dst_id ) then
            tund_info[ :resend_singles ][ dst_id ] = ( tund_info[ :resend_singles ][ dst_id ] + miss_pack_ids ).uniq
          else
            tund_info[ :resend_singles ][ dst_id ] = miss_pack_ids
          end

          add_write( tund )
        when RANGE_MISS then
          dst_id, *ranges = data[ 9..-1 ].unpack( 'nQ>*' )

          return if ranges.empty? || ranges.size % 2 != 0

          dst = tund_info[ :dsts ][ dst_id ]
          return unless dst

          # puts "debug1 #{ now } got range miss #{ dst_id } #{ ranges[ 0, 100 ].inspect }"

          dst_info = @dst_infos[ dst ]
          miss_pack_ids = []
          idx = 0

          while idx < ranges.size do
            miss_pack_ids += dst_info[ :wafters ].select{ | pack_id, _ | ( pack_id >= ranges[ idx ] ) && ( pack_id <= ranges[ idx + 1 ] ) }.keys
            idx += 2
          end

          if miss_pack_ids.any? then
            if tund_info[ :resend_ranges ].include?( dst_id ) then
              tund_info[ :resend_ranges ][ dst_id ] = ( tund_info[ :resend_ranges ][ dst_id ] + miss_pack_ids ).uniq
            else
              tund_info[ :resend_ranges ][ dst_id ] = miss_pack_ids
            end

            add_write( tund )
          end
        when CONTINUE then
          dst_id, complete_pack_id = data[ 9, 10 ].unpack( 'nQ>' )

          # puts "debug1 #{ now } got continue #{ dst_id } #{ complete_pack_id }"

          dst = tund_info[ :dsts ][ dst_id ]
          return unless dst

          dst_info = @dst_infos[ dst ]
          dst_info[ :wafters ].delete_if{ | pack_id, _ | pack_id <= complete_pack_id }

          if dst_info[ :wafters ].any? && !tund_info[ :resend_newers ].include?( dst_id ) then
            tund_info[ :resend_newers ][ dst_id ] = dst_info[ :wafters ].keys
            add_write( tund )
          end
        when FIN1 then
          src_id, fin1_src_pack_id = data[ 9, 16 ].unpack( 'Q>Q>' )

          # puts "debug1 got fin1 #{ src_id } #{ fin1_src_pack_id }"

          dst_id = tund_info[ :dst_ids ][ src_id ]
          return unless dst_id

          dst = tund_info[ :dsts ][ dst_id ]
          return unless dst

          dst_info = @dst_infos[ dst ]
          # 对面可能同时读到和写到reset，导致发出两条fin1
          return if dst_info.nil? || dst_info[ :fin1_src_pack_id ]

          dst_info[ :fin1_src_pack_id ] = fin1_src_pack_id

          # puts "debug1 continue recv src to #{ dst_info[ :continue_recv_pack_id ] } dst.wbuff.empty? #{ dst_info[ :wbuff ].empty? }"

          if ( dst_info[ :continue_recv_pack_id ] == fin1_src_pack_id ) && dst_info[ :wbuff ].empty? then
            dst.close_write
            dst_info[ :closed_write ] = true
            @writes.delete( dst )

            # puts "debug1 add ctlmsg fin2"
            add_ctlmsg_fin2( dst_info )

            if dst_info[ :src_fin2 ] then
              # puts "debug1 读tund -> 读到fin1，得到对面src最终包id -> 已连续写入至src最终包id？ -> 关dst写 -> 发fin2 -> dst.src_fin2？ -> 删dst.ext"
              @roles.delete( dst )
              del_dst_ext( dst )
            end
          end
        when FIN2 then
          src_id = data[ 9, 8 ].unpack( 'Q>' ).first

          # puts "debug1 got fin2 #{ src_id }"

          dst_id = tund_info[ :dst_ids ][ src_id ]
          return unless dst_id

          dst = tund_info[ :dsts ][ dst_id ]
          return unless dst

          dst_info = @dst_infos[ dst ]
          return if dst_info.nil? || dst_info[ :src_fin2 ]

          dst_info[ :src_fin2 ] = true

          if dst.closed? then
            # puts "debug1 读tund -> 读到fin2，对面已结束写 -> dst.src_fin2置true -> dst已双向关？ -> 删dst.ext"
            @roles.delete( dst )
            del_dst_ext( dst )
          end
        when TUN_FIN then
          puts "p#{ Process.pid } #{ Time.new } recv tun fin"
          set_tund_is_closing( tund )
        end

        return
      end

      src_id = data[ 8, 8 ].unpack( 'Q>' ).first

      dst_id = tund_info[ :dst_ids ][ src_id ]
      return unless dst_id

      dst = tund_info[ :dsts ][ dst_id ]
      return if dst.nil? || dst.closed?

      dst_info = @dst_infos[ dst ]
      return if ( pack_id <= dst_info[ :continue_recv_pack_id ] ) || dst_info[ :pieces ].include?( pack_id )

      data = data[ 16..-1 ]

      if pack_id <= CONFUSE_UNTIL then
        data = @custom.decode( data )
        # puts "debug3 decoded pack #{ pack_id } #{ data.bytesize }\n#{ data.inspect }\n\n"
      end

      # 放进dst wbuff，跳号放碎片缓存，发确认
      if pack_id - dst_info[ :continue_recv_pack_id ] == 1 then
        while dst_info[ :pieces ].include?( pack_id + 1 ) do
          data << dst_info[ :pieces ].delete( pack_id + 1 )
          pack_id += 1
        end

        dst_info[ :continue_recv_pack_id ] = pack_id
        dst_info[ :wbuff ] << data
        dst_info[ :last_recv_at ] = now
        add_write( dst )
      else
        dst_info[ :pieces ][ pack_id ] = data
        dst_info[ :last_recv_at ] = now
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
          return
        else
          @proxyd_info[ :ctlmsgs ].shift
        end
      end

      @writes.delete( proxyd )
    end

    ##
    # write dst
    #
    def write_dst( dst )
      dst_info = @dst_infos[ dst ]
      return if dst_info[ :closed_write ]

      # 处理关闭
      if dst_info[ :is_closing ] then
        close_dst( dst )
        return
      end

      # 处理wbuff
      data = dst_info[ :wbuff ]

      unless data.empty? then
        begin
          written = dst.write_nonblock( data )
        rescue IO::WaitWritable, Errno::EINTR
          return
        rescue Exception => e
          # puts "debug1 write dst #{ e.class }"
          close_dst( dst )
          return
        end

        # puts "debug3 written dst #{ written }"
        data = data[ written..-1 ]
        dst_info[ :wbuff ] = data
      end

      unless data.empty? then
        puts "p#{ Process.pid } #{ Time.new } write dst cutted? written #{ written } left #{ data.bytesize }"
        return
      end

      if dst_info[ :fin1_src_pack_id ] && ( dst_info[ :continue_recv_pack_id ] == dst_info[ :fin1_src_pack_id ] ) then
        dst.close_write
        dst_info[ :closed_write ] = true

        # puts "debug1 after write dst, close dst write and add ctlmsg fin2"
        add_ctlmsg_fin2( dst_info )

        if dst_info[ :src_fin2 ] then
          # puts "debug1 写dst -> 写光dst.wbuff -> 已连续写入至src最终包id？ -> 关dst写 -> 发fin2 -> dst.src_fin2？ -> 删dst.ext"
          @roles.delete( dst )
          del_dst_ext( dst )
        end
      end

      @writes.delete( dst )
    end

    ##
    # write tund
    #
    def write_tund( tund )
      tund_info = @tund_infos[ tund ]

      # 处理关闭
      if tund_info[ :is_closing ] then
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
          # puts "debug1 #{ Time.new } wait send ctlmsg left #{ tund_info[ :ctlmsgs ].size }"
          return
        end

        tund_info[ :ctlmsgs ].shift
      end

      resend_newers = tund_info[ :resend_newers ]
      resend_singles = tund_info[ :resend_singles ]
      resend_ranges = tund_info[ :resend_ranges ]

      resend_newers.each do | dst_id, newer_pack_ids |
        dst = tund_info[ :dsts ][ dst_id ]

        if dst then
          dst_info = @dst_infos[ dst ]

          while newer_pack_ids.any? do
            pack_id = newer_pack_ids.first
            data = dst_info[ :wafters ][ pack_id ]

            if data then
              sent = send_data( tund, data, tund_info[ :tun_addr ] )

              if sent == :fatal then
                close_tund( tund )
                return
              elsif sent == :wait then
                # puts "debug1 #{ Time.new } wait resend newer at #{ pack_id } left #{ newer_pack_ids.size }"
                dst_info[ :last_sent_at ] = now
                return
              else
                dst_info[ :last_sent_at ] = now
              end
            end

            newer_pack_ids.shift
          end
        end

        resend_newers.delete( dst_id )
      end

      resend_singles.each do | dst_id, miss_pack_ids |
        dst = tund_info[ :dsts ][ dst_id ]

        if dst then
          dst_info = @dst_infos[ dst ]

          while miss_pack_ids.any? do
            pack_id = miss_pack_ids.first
            data = dst_info[ :wafters ][ pack_id ]

            if data then
              sent = send_data( tund, data, tund_info[ :tun_addr ] )

              if sent == :fatal then
                close_tund( tund )
                return
              elsif sent == :wait then
                # puts "debug1 #{ Time.new } wait resend single at #{ pack_id } left #{ miss_pack_ids.size }"
                dst_info[ :last_sent_at ] = now
                return
              else
                dst_info[ :last_sent_at ] = now
              end
            end

            miss_pack_ids.shift
          end
        end

        resend_singles.delete( dst_id )
      end

      resend_ranges.each do | dst_id, miss_pack_ids |
        dst = tund_info[ :dsts ][ dst_id ]

        if dst then
          dst_info = @dst_infos[ dst ]

          while miss_pack_ids.any? do
            pack_id = miss_pack_ids.first
            data = dst_info[ :wafters ][ pack_id ]

            if data then
              sent = send_data( tund, data, tund_info[ :tun_addr ] )

              if sent == :fatal then
                close_tund( tund )
                return
              elsif sent == :wait then
                # puts "debug1 #{ Time.new } wait resend range at #{ pack_id } left #{ miss_pack_ids.size }"
                dst_info[ :last_sent_at ] = now
                return
              else
                dst_info[ :last_sent_at ] = now
              end
            end

            miss_pack_ids.shift
          end
        end

        resend_ranges.delete( dst_id )
      end

      # 处理event dsts
      while tund_info[ :event_dsts ].any? do
        dst = tund_info[ :event_dsts ].first
        dst_info = @dst_infos[ dst ]
        dst_id = dst_info[ :id ]
        rbuff = dst_info[ :rbuff ]

        unless rbuff.empty? then
          len = rbuff.bytesize
          written = 0
          idx = 0

          while idx < len do
            chunk = rbuff[ idx, PACK_SIZE ]
            chunk_size = chunk.bytesize
            pack_id = dst_info[ :biggest_pack_id ] + 1

            if pack_id <= CONFUSE_UNTIL then
              # puts "debug3 encode chunk #{ pack_id } #{ chunk_size }\n#{ chunk.inspect }\n\n"
              chunk = @custom.encode( chunk )
            end

            data = [ [ pack_id, dst_id ].pack( 'Q>n' ), chunk ].join
            sent = send_data( tund, data, tund_info[ :tun_addr ] )

            if sent == :fatal then
              close_tund( tund )
              return
            elsif sent == :wait then
              # puts "debug1 #{ Time.new } wait relay dst.rbuff at #{ pack_id }"
              rbuff = rbuff[ written..-1 ]
              dst_info[ :rbuff ] = rbuff
              dst_info[ :last_sent_at ] = now
              return
            end

            dst_info[ :wafters ][ pack_id ] = data
            dst_info[ :biggest_pack_id ] = pack_id
            written += chunk_size
            idx += PACK_SIZE
          end

          if written != len then
            puts "p#{ Process.pid } #{ Time.new } relay dst.rbuff cutted? #{ written }/#{ len }"
            return
          end

          dst_info[ :rbuff ].clear
          dst_info[ :last_sent_at ] = now

          # 写后超过上限，暂停读src
          if dst_info[ :wafters ].size >= WAFTERS_LIMIT then
            puts "p#{ Process.pid } #{ Time.new } pause dst #{ dst_id } #{ dst_info[ :domain_port ] } #{ dst_info[ :biggest_pack_id ] }"
            @reads.delete( dst )
            dst_info[ :paused ] = true
          end
        end

        if dst_info[ :closed_read ] then
          # puts "debug1 写tund -> 转光dst.rbuff -> dst已关读？ -> 发fin1"
          add_ctlmsg_fin1( dst_info )
        end

        tund_info[ :event_dsts ].shift
      end

      tund_info[ :last_sent_at ] = now

      if tund_info[ :ctlmsgs ].empty? && tund_info[ :event_dsts ].empty? then
        @writes.delete( tund )
      end
    end

  end
end
