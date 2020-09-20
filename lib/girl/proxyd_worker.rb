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
      @pause_dsts = []
      @roles = {}           # sock => :dotr / :proxyd / :dst / :tund
      @dst_infos = {}       # dst => {}
      @tunds = {}           # port => tund
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
          # 先写，再读
          ws.each do | sock |
            case @roles[ sock ]
            when :dst
              write_dst( sock )
            when :tund
              write_tund( sock )
            end
          end

          rs.each do | sock |
            case @roles[ sock ]
            when :dotr
              read_dotr( sock )
            when :proxyd
              read_proxyd( sock )
            when :dst
              read_dst( sock )
            when :tund
              read_tund( sock )
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
        if !tund.closed? && tund_info[ :tun_addr ]
          # puts "debug1 send tund fin"
          tund.sendmsg( data, 0, tund_info[ :tun_addr ] )
        end
      end

      # puts "debug1 exit"
      exit
    end

    private

    ##
    # loop check expire
    #
    def loop_check_expire
      Thread.new do
        loop do
          sleep CHECK_EXPIRE_INTERVAL

          @mutex.synchronize do
            need_trigger = false
            now = Time.new

            @tund_infos.each do | tund, tund_info |
              unless tund.closed?
                is_expired = tund_info[ :last_recv_at ] ? ( now - tund_info[ :last_recv_at ] > EXPIRE_AFTER ) : ( now - tund_info[ :created_at ] > EXPIRE_NEW )

                if is_expired
                  puts "p#{ Process.pid } #{ Time.new } expire tund #{ tund_info[ :port ] }"
                  set_is_closing( tund )
                  need_trigger = true
                else
                  data = [ 0, HEARTBEAT, rand( 128 ) ].pack( 'Q>CC' )
                  # puts "debug1 #{ Time.new } #{ tund_info[ :port ] } heartbeat"
                  send_data( tund, data, tund_info[ :tun_addr ] )
                  del_dst_ids = []

                  tund_info[ :dsts ].each do | dst_id, dst |
                    if dst.closed?
                      dst_info = @dst_infos[ dst ]

                      if dst_info && ( now - dst_info[ :last_continue_at ] > EXPIRE_AFTER )
                        puts "p#{ Process.pid } #{ Time.new } expire dst ext #{ dst_info[ :domain_port ] }"
                        tund_info[ :wmems ].delete_if { | port_and_pack_id, _ | port_and_pack_id.first == dst_id }
                        tund_info[ :dst_ids ].delete( dst_info[ :src_id ] )
                        @dst_infos.delete( dst )
                        del_dst_ids << dst_id
                      end
                    end
                  end

                  if del_dst_ids.any?
                    tund_info[ :dsts ].delete_if { | dst_id, _ | del_dst_ids.include?( dst_id ) }
                  end
                end
              end
            end

            @dst_infos.each do | dst, dst_info |
              if now - dst_info[ :last_continue_at ] > EXPIRE_AFTER
                puts "p#{ Process.pid } #{ Time.new } expire dst #{ dst_info[ :domain_port ] }"
                set_is_closing( dst )
                need_trigger = true
              end
            end

            if need_trigger
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
            need_trigger = false

            if @tunds.any?
              @tunds.each do | tund_port, tund |
                tund_info = @tund_infos[ tund ]

                if tund_info[ :dsts ].any?
                  now = Time.new

                  tund_info[ :dsts ].each do | dst_id, dst |
                    dst_info = @dst_infos[ dst ]

                    if dst_info && ( now - dst_info[ :last_continue_at ] < SEND_STATUS_UNTIL )
                      data = [ 0, DEST_STATUS, dst_id, dst_info[ :biggest_pack_id ], dst_info[ :continue_src_pack_id ] ].pack( 'Q>CnQ>Q>' )
                      send_data( tund, data, tund_info[ :tun_addr ] )
                    end
                  end
                end
              end
            end

            if @pause_dsts.any?
              resume_dsts = []
              ignore_dsts = []

              @pause_dsts.each do | dst |
                dst_info = @dst_infos[ dst ]

                if dst_info
                  tund = dst_info[ :tund ]

                  if tund.closed?
                    ignore_dsts << dst
                  else
                    tund_info = @tund_infos[ tund ]

                    if tund_info[ :wmems ].size < RESUME_BELOW
                      puts "p#{ Process.pid } #{ Time.new } resume dst #{ dst_info[ :domain_port ] }"
                      resume_dsts << dst
                    end
                  end
                else
                  ignore_dsts << dst
                end
              end

              if resume_dsts.any?
                resume_dsts.each do | dst |
                  add_read( dst )
                end

                @pause_dsts -= resume_dsts
                need_trigger = true
              end

              if ignore_dsts.any?
                @pause_dsts -= ignore_dsts
              end
            end

            if need_trigger
              next_tick
            end
          end
        end
      end
    end

    ##
    # resolve domain
    #
    def resolve_domain( tund, src_id, domain_port )
      resolv_cache = @resolv_caches[ domain_port ]

      if resolv_cache
        destination_addr, created_at = resolv_cache

        if Time.new - created_at < RESOLV_CACHE_EXPIRE
          # puts "debug1 #{ domain_port } hit resolv cache #{ Addrinfo.new( destination_addr ).inspect }"
          deal_with_destination_addr( tund, src_id, destination_addr, domain_port )
          return
        end

        # puts "debug1 expire #{ domain_port } resolv cache"
        @resolv_caches.delete( domain_port )
      end

      Thread.new do
        colon_idx = domain_port.rindex( ':' )

        if colon_idx
          destination_domain = domain_port[ 0...colon_idx ]
          destination_port = domain_port[ ( colon_idx + 1 )..-1 ].to_i

          begin
            destination_addr = Socket.sockaddr_in( destination_port, destination_domain )
          rescue Exception => e
            puts "p#{ Process.pid } #{ Time.new } sockaddr in #{ domain_port } #{ e.class }"
          end
        end

        @mutex.synchronize do
          if destination_addr
            # puts "debug1 resolved #{ domain_port } #{ Addrinfo.new( destination_addr ).inspect }"
            @resolv_caches[ domain_port ] = [ destination_addr, Time.new ]

            unless tund.closed?
              if deal_with_destination_addr( tund, src_id, destination_addr, domain_port )
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
        id: dst_id,                 # id
        tund: tund,                 # 对应tund
        domain_port: domain_port,   # 域名和端口
        biggest_pack_id: 0,         # 最大包号码
        wbuff: '',                  # 写前
        src_id: src_id,             # 近端src id
        send_ats: {},               # 上一次发出时间 pack_id => send_at
        continue_src_pack_id: 0,    # 收到几
        pieces: {},                 # 跳号包 src_pack_id => data
        is_src_closed: false,       # src是否已关闭
        biggest_src_pack_id: 0,     # src最大包号码
        completed_pack_id: 0,       # 完成到几（对面收到几）
        last_continue_at: Time.new, # 上一次发生流量的时间
        is_closing: false           # 是否准备关闭
      }

      add_read( dst, :dst )

      tund_info = @tund_infos[ tund ]
      tund_info[ :dst_ids ][ src_id ] = dst_id
      tund_info[ :dsts ][ dst_id ] = dst

      data = [ 0, PAIRED, src_id, dst_id ].pack( 'Q>CQ>n' )
      # puts "debug1 send paired #{ data.inspect }"
      send_data( tund, data, tund_info[ :tun_addr ] )

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
      add_read( proxyd, :proxyd )
    end

    ##
    # add read
    #
    def add_read( sock, role = nil )
      if sock && !sock.closed? && !@reads.include?( sock )
        @reads << sock

        if role
          @roles[ sock ] = role
        end
      end
    end

    ##
    # add write
    #
    def add_write( sock )
      if sock && !sock.closed? && !@writes.include?( sock )
        @writes << sock
      end
    end

    ##
    # add pause dst
    #
    def add_pause_dst( dst )
      @reads.delete( dst )

      unless @pause_dsts.include?( dst )
        @pause_dsts << dst
      end
    end

    ##
    # set is closing
    #
    def set_is_closing( sock )
      if sock && !sock.closed?
        role = @roles[ sock ]
        # puts "debug1 set #{ role.to_s } is closing"

        case role
        when :dst
          dst_info = @dst_infos[ sock ]
          dst_info[ :is_closing ] = true
        when :tund
          tund_info = @tund_infos[ sock ]
          tund_info[ :is_closing ] = true
        end

        @reads.delete( sock )
        add_write( sock )
      end
    end

    ##
    # tunnel data
    #
    def tunnel_data( dst, data )
      dst_info = @dst_infos[ dst ]
      tund = dst_info[ :tund ]

      if tund.closed?
        puts "p#{ Process.pid } #{ Time.new } tund closed, close dst"
        set_is_closing( dst )
        return
      end

      tund_info = @tund_infos[ tund ]
      dst_id = dst_info[ :id ]
      now = Time.new
      pack_id = dst_info[ :biggest_pack_id ]
      idx = 0
      len = data.bytesize

      while idx < len
        chunk = data[ idx, PACK_SIZE ]
        pack_id += 1

        if pack_id <= CONFUSE_UNTIL
          chunk = @custom.encode( chunk )
          # puts "debug1 encoded chunk #{ pack_id }"
        end

        data2 = [ [ pack_id, dst_id ].pack( 'Q>n' ), chunk ].join
        sent = send_data( tund, data2, tund_info[ :tun_addr ] )
        # puts "debug2 written pack #{ pack_id } #{ sent }"
        tund_info[ :wmems ][ [ dst_id, pack_id ] ] = data2
        dst_info[ :send_ats ][ pack_id ] = now
        idx += PACK_SIZE
      end

      dst_info[ :biggest_pack_id ] = pack_id
      dst_info[ :last_continue_at ] = now

      # 写后超过上限，暂停读dst
      if tund_info[ :wmems ].size >= WMEMS_LIMIT
        puts "p#{ Process.pid } #{ Time.new } pause dst #{ dst_id } #{ dst_info[ :domain_port ] } #{ dst_info[ :biggest_pack_id ] }"
        add_pause_dst( dst )
      end
    end

    ##
    # send data
    #
    def send_data( sock, data, to_addr )
      begin
        sock.sendmsg( data, 0, to_addr )
      rescue IO::WaitWritable, Errno::EINTR
        return false
      rescue Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENETDOWN => e
        if @roles[ sock ] == :tund
          puts "#{ Time.new } #{ e.class }, close tund"
          close_tund( sock )
          return false
        end
      end

      true
    end

    ##
    # close dst
    #
    def close_dst( dst )
      # puts "debug1 close dst"
      close_sock( dst )
      @pause_dsts.delete( dst )
      dst_info = @dst_infos[ dst ]
      tund = dst_info[ :tund ]

      if tund.closed?
        @dst_infos.delete( dst )
        return
      end

      tund_info = @tund_infos[ tund ]
      dst_id = dst_info[ :id ]

      if dst_info[ :is_src_closed ]
        # puts "debug1 4-3. after close dst -> src closed ? yes -> del dst ext -> send fin2"
        del_dst_ext( tund_info, dst_id )
        data = [ 0, FIN2, dst_id ].pack( 'Q>Cn' )
      else
        # puts "debug1 3-1. after close dst -> src closed ? no -> send fin1"
        data = [ 0, FIN1, dst_id, dst_info[ :biggest_pack_id ], dst_info[ :continue_src_pack_id ] ].pack( 'Q>CnQ>Q>' )
      end

      send_data( tund, data, tund_info[ :tun_addr ] )
    end

    ##
    # close tun
    #
    def close_tund( tund )
      # puts "debug1 close tund"
      close_sock( tund )
      tund_info = @tund_infos.delete( tund )
      tund_info[ :dsts ].each{ | _, dst | set_is_closing( dst ) }
      @tunneling_tunds.delete( tund_info[ :tun_addr ] )
      @tunds.delete( tund_info[ :port ] )
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
    # del dst ext
    #
    def del_dst_ext( tund_info, dst_id )
      tund_info[ :wmems ].delete_if { | port_and_pack_id, _ | port_and_pack_id.first == dst_id }
      dst = tund_info[ :dsts ].delete( dst_id )

      if dst
        dst_info = @dst_infos.delete( dst )

        if dst_info
          tund_info[ :dst_ids ].delete( dst_info[ :src_id ] )
        end
      end
    end

    ##
    # release wmems
    #
    def release_wmems( tund_info, dst_info, completed_pack_id )
      if completed_pack_id > dst_info[ :completed_pack_id ]
        # puts "debug2 update completed pack #{ completed_pack_id }"

        pack_ids = dst_info[ :send_ats ].keys.select { | pack_id | pack_id <= completed_pack_id }

        pack_ids.each do | pack_id |
          tund_info[ :wmems ].delete( [ dst_info[ :id ], pack_id ] )
          dst_info[ :send_ats ].delete( pack_id )
        end

        dst_info[ :completed_pack_id ] = completed_pack_id
      end
    end

    ##
    # next tick
    #
    def next_tick
      @dotw.write( '.' )
    end

    ##
    # write dst
    #
    def write_dst( dst )
      dst_info = @dst_infos[ dst ]

      if dst_info[ :is_closing ]
        close_dst( dst )
        return
      end

      data = dst_info[ :wbuff ]

      if data.empty?
        @writes.delete( dst )
        return
      end

      begin
        written = dst.write_nonblock( data )
      rescue IO::WaitWritable, Errno::EINTR
        return
      rescue Exception => e
        # puts "debug1 write dst #{ e.class }"
        close_dst( dst )
        return
      end

      # puts "debug2 write dst #{ written }"
      data = data[ written..-1 ]
      dst_info[ :wbuff ] = data
      dst_info[ :last_continue_at ] = Time.new
    end

    ##
    # write tund
    #
    def write_tund( tund )
      tund_info = @tund_infos[ tund ]

      if tund_info[ :is_closing ]
        if tund_info[ :changed_tun_addr ]
          data = [ 0, IP_CHANGED ].pack( 'Q>C' )
          send_data( tund, data, tund_info[ :changed_tun_addr ] )
        end

        close_tund( tund )
        return
      end

      @writes.delete( tund )
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

      if @tunneling_tunds.include?( from_addr )
        tund = @tunneling_tunds[ from_addr ]
        tund_info = @tund_infos[ tund ]
        port = tund_info[ :port ]
        data = [ 0, TUND_PORT, port ].pack( 'Q>Cn' )
        puts "p#{ Process.pid } #{ Time.new } resend tund port #{ port }"
        send_data( proxyd, data, from_addr )
        return
      end

      result = @custom.check( data, addrinfo )

      if result != :success
        puts "p#{ Process.pid } #{ Time.new } #{ result }"
        return
      end

      tund = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      tund.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )
      port = tund.local_address.ip_port

      @tunneling_tunds[ from_addr ] = tund
      @tunds[ port ] = tund
      @tund_infos[ tund ] = {
        port: port,           # 端口
        wbuffs: [],           # 写前 [ dst_id, pack_id, data ]
        wmems: {},            # 写后 [ dst_id, pack_id ] => data
        tun_addr: from_addr,  # tun地址
        dsts: {},             # dst额外信息 dst_id => dst
        dst_ids: {},          # src_id => dst_id
        created_at: Time.new, # 创建时间
        last_recv_at: nil,    # 上一次收到流量的时间，过期关闭
        is_closing: false,    # 是否准备关闭
        changed_tun_addr: nil # 记录到和tun addr不符的来源地址
      }

      add_read( tund, :tund )

      data = [ 0, TUND_PORT, port ].pack( 'Q>Cn' )
      puts "p#{ Process.pid } #{ Time.new } a new tunnel #{ addrinfo.ip_unpack.inspect } - #{ port }, #{ @tunds.size } tunds"
      send_data( proxyd, data, from_addr )
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
        set_is_closing( dst )
        return
      end

      tunnel_data( dst, data )
    end

    ##
    # read tund
    #
    def read_tund( tund )
      data, addrinfo, rflags, *controls = tund.recvmsg
      from_addr = addrinfo.to_sockaddr
      now = Time.new
      tund_info = @tund_infos[ tund ]

      if from_addr != tund_info[ :tun_addr ]
        # 通常是光猫刷新ip（端口也会变），但万一不是，为了避免脏数据注入，关闭tund
        puts "p#{ Process.pid } #{ Time.new } from #{ addrinfo.inspect } not match tun addr #{ Addrinfo.new( tund_info[ :tun_addr ] ).inspect }"
        tund_info[ :changed_tun_addr ] = from_addr
        set_is_closing( tund )
        return
      end

      tund_info[ :last_recv_at ] = now
      pack_id = data[ 0, 8 ].unpack( 'Q>' ).first

      if pack_id == 0
        ctl_num = data[ 8 ].unpack( 'C' ).first

        case ctl_num
        when A_NEW_SOURCE
          src_id = data[ 9, 8 ].unpack( 'Q>' ).first
          dst_id = tund_info[ :dst_ids ][ src_id ]

          if dst_id
            dst = tund_info[ :dsts ][ dst_id ]
            return unless dst

            if dst.closed?
              dst_id = 0
            end

            # puts "debug1 resend paired #{ dst_id }"
            data2 = [ 0, PAIRED, src_id, dst_id ].pack( 'Q>CQ>n' )
            send_data( tund, data2, tund_info[ :tun_addr ] )
            return
          end

          data = data[ 17..-1 ]
          domain_port = @custom.decode( data )
          puts "p#{ Process.pid } #{ Time.new } a new source #{ src_id } #{ domain_port }"
          resolve_domain( tund, src_id, domain_port )
        when SOURCE_STATUS
          src_id, relay_src_pack_id, continue_dst_pack_id  = data[ 9, 24 ].unpack( 'Q>Q>Q>' )

          dst_id = tund_info[ :dst_ids ][ src_id ]
          return unless dst_id

          dst = tund_info[ :dsts ][ dst_id ]
          return unless dst

          dst_info = @dst_infos[ dst ]
          return unless dst_info

          # puts "debug2 got source status #{ Time.new }"

          # 消写后
          release_wmems( tund_info, dst_info, continue_dst_pack_id )

          # 发miss
          if !dst.closed? && ( dst_info[ :continue_src_pack_id ] < relay_src_pack_id )
            ranges = []
            ignored = false
            curr_pack_id = dst_info[ :continue_src_pack_id ] + 1

            dst_info[ :pieces ].keys.sort.each do | pack_id |
              if pack_id > curr_pack_id
                ranges << [ curr_pack_id, pack_id - 1 ]

                if ranges.size >= MISS_RANGE_LIMIT
                  puts "p#{ Process.pid } #{ Time.new } break add miss range at #{ pack_id }"
                  ignored = true
                  break
                end
              end

              curr_pack_id = pack_id + 1
            end

            if !ignored && ( curr_pack_id <= relay_src_pack_id )
              ranges << [ curr_pack_id, relay_src_pack_id ]
            end

            # puts "debug1 continue/relay #{ dst_info[ :continue_src_pack_id ] }/#{ relay_src_pack_id } send MISS #{ ranges.size }"
            idx = 0
            ranges = ranges.map{ | pack_id_begin, pack_id_end | [ pack_id_begin, pack_id_end ].pack( 'Q>Q>' ) }

            while idx < ranges.size
              chunk = ranges[ idx, MULTI_MISS_SIZE ].join
              data2 = [ [ 0, MULTI_MISS, src_id ].pack( 'Q>CQ>' ), chunk ].join
              send_data( tund, data2, tund_info[ :tun_addr ] )
              idx += MULTI_MISS_SIZE
            end
          end
        when MULTI_MISS
          dst_id, *ranges = data[ 9..-1 ].unpack( 'nQ>*' )

          dst = tund_info[ :dsts ][ dst_id ]
          return unless dst

          dst_info = @dst_infos[ dst ]
          return unless dst_info

          return if ranges.empty? || ( ranges.size % 2 != 0 )

          # puts "debug1 got multi miss #{ dst_id } #{ ranges.size }"

          idx = 0

          while idx < ranges.size
            pack_id_begin, pack_id_end = ranges[ idx ], ranges[ idx + 1 ]

            ( pack_id_begin..pack_id_end ).each do | pack_id |
              send_at = dst_info[ :send_ats ][ pack_id ]

              if send_at
                break if now - send_at < CHECK_STATUS_INTERVAL
                data2 = tund_info[ :wmems ][ [ dst_id, pack_id ] ]

                if data2
                  if send_data( tund, data2, tund_info[ :tun_addr ] )
                    dst_info[ :last_continue_at ] = now
                  end
                end
              end
            end

            idx += 2
          end
        when MISS
          dst_id, pack_id_begin, pack_id_end = data[ 9, 18 ].unpack( 'nQ>Q>' )

          dst = tund_info[ :dsts ][ dst_id ]
          return unless dst

          dst_info = @dst_infos[ dst ]
          return unless dst_info

          ( pack_id_begin..pack_id_end ).each do | pack_id |
            send_at = dst_info[ :send_ats ][ pack_id ]

            if send_at
              break if now - send_at < CHECK_STATUS_INTERVAL
              data2 = tund_info[ :wmems ][ [ dst_id, pack_id ] ]

              if data2
                if send_data( tund, data2, tund_info[ :tun_addr ] )
                  dst_info[ :last_continue_at ] = now
                end
              end
            end
          end
        when FIN1
          src_id, biggest_src_pack_id, continue_dst_pack_id = data[ 9, 24 ].unpack( 'Q>Q>Q>' )

          dst_id = tund_info[ :dst_ids ][ src_id ]
          return unless dst_id

          dst = tund_info[ :dsts ][ dst_id ]
          return unless dst

          dst_info = @dst_infos[ dst ]
          return unless dst_info

          # puts "debug1 got fin1 #{ src_id } biggest src pack #{ biggest_src_pack_id } completed dst pack #{ continue_dst_pack_id }"
          dst_info[ :is_src_closed ] = true
          dst_info[ :biggest_src_pack_id ] = biggest_src_pack_id
          release_wmems( tund_info, dst_info, continue_dst_pack_id )

          if biggest_src_pack_id == dst_info[ :continue_src_pack_id ]
            # puts "debug1 4-1. tund recv fin1 -> all traffic received ? -> close dst after write"
            set_is_closing( dst )
          end
        when FIN2
          src_id = data[ 9, 8 ].unpack( 'Q>' ).first

          dst_id = tund_info[ :dst_ids ][ src_id ]
          return unless dst_id

          # puts "debug1 3-2. tund recv fin2 -> del dst ext"
          del_dst_ext( tund_info, dst_id )
        when TUN_FIN
          puts "p#{ Process.pid } #{ Time.new } recv tun fin"
          set_is_closing( tund )
        end

        return
      end

      src_id = data[ 8, 8 ].unpack( 'Q>' ).first

      dst_id = tund_info[ :dst_ids ][ src_id ]
      return unless dst_id

      dst = tund_info[ :dsts ][ dst_id ]
      return unless dst

      dst_info = @dst_infos[ dst ]
      return unless dst_info

      return if ( pack_id <= dst_info[ :continue_src_pack_id ] ) || dst_info[ :pieces ].include?( pack_id )

      data = data[ 16..-1 ]
      # puts "debug2 got pack #{ pack_id }"

      if pack_id <= CONFUSE_UNTIL
        # puts "debug2 #{ data.inspect }"
        data = @custom.decode( data )
        # puts "debug1 decoded pack #{ pack_id }"
      end

      # 放进写前，跳号放碎片缓存
      if pack_id - dst_info[ :continue_src_pack_id ] == 1
        while dst_info[ :pieces ].include?( pack_id + 1 )
          data << dst_info[ :pieces ].delete( pack_id + 1 )
          pack_id += 1
        end

        dst_info[ :continue_src_pack_id ] = pack_id
        dst_info[ :last_continue_at ] = now
        dst_info[ :wbuff ] << data
        add_write( dst )
        # puts "debug2 update continue src pack #{ pack_id }"

        # 若对面已关闭，且流量正好收全，关闭dst
        if dst_info[ :is_src_closed ] && ( pack_id == dst_info[ :biggest_src_pack_id ] )
          # puts "debug1 4-2. tund recv traffic -> src closed and all traffic received ? -> close dst after write"
          set_is_closing( dst )
        end
      elsif !dst_info[ :pieces ].include?( pack_id )
        dst_info[ :pieces ][ pack_id ] = data
        dst_info[ :last_continue_at ] = now
      end
    end

  end
end
