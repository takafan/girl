module Girl
  class MirrordWorker

    ##
    # initialize
    #
    def initialize( mirrord_port, infod_port, p2d_ports, p2d_host )
      @p2d_host = p2d_host
      @reads = []
      @writes = []
      @roles = {}                    # :dotr / :mirrord / :infod / :p1d / :p2d / :p1 / :p2
      @room_infos = {}               # im => { :mirrord, :p1_addrinfo, :updated_at, :p1d, :p2d }
      @p1d_infos = {}                # p1d => { :im }
      @p2d_infos = {}                # p2d => { :im }
      @p1_infos = {}                 # p1 => { :addrinfo, :im, :p2, :wbuff, :closing_write, :paused }
      @p2_infos = ConcurrentHash.new # p2 => { :addrinfo, :im, :p1, :rbuff, :wbuff, :created_at,
                                     #         :last_recv_at, :last_sent_at, :closing, :closing_write, :paused }

      set_p2d_ports( p2d_ports )
      new_a_pipe
      new_mirrords( mirrord_port )
      new_a_infod( infod_port )
    end

    ##
    # looping
    #
    def looping
      puts "#{ Time.new } looping"
      loop_check_expire

      loop do
        rs, ws = IO.select( @reads, @writes )

        rs.each do | sock |
          role = @roles[ sock ]

          case role
          when :dotr then
            read_dotr( sock )
          when :mirrord
            read_mirrord( sock )
          when :infod
            read_infod( sock )
          when :p1d
            read_p1d( sock )
          when :p2d
            read_p2d( sock )
          when :p1
            read_p1( sock )
          when :p2
            read_p2( sock )
          else
            puts "#{ Time.new } read unknown role #{ role }"
          end
        end

        ws.each do | sock |
          role = @roles[ sock ]

          case role
          when :p1 then
            write_p1( sock )
          when :p2 then
            write_p2( sock )
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
    # add p1 wbuff
    #
    def add_p1_wbuff( p1, data )
      return if p1.nil? || p1.closed?
      p1_info = @p1_infos[ p1 ]
      p1_info[ :wbuff ] << data
      add_write( p1 )

      if p1_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        p2 = p1_info[ :p2 ]

        if p2 then
          p2_info = @p2_infos[ p2 ]

          if p2_info then
            puts "#{ Time.new } pause p2 #{ p2_info[ :im ].inspect } #{ p2_info[ :addrinfo ].inspect }"
            @reads.delete( p2 )
            p2_info[ :paused ] = true
          end
        end
      end
    end

    ##
    # add p2 rbuff
    #
    def add_p2_rbuff( p2, data )
      return if p2.nil? || p2.closed?
      p2_info = @p2_infos[ p2 ]
      return if p2_info[ :closing ]
      p2_info[ :rbuff ] << data

      if p2_info[ :rbuff ].bytesize >= WBUFF_LIMIT then
        # puts "debug p2.rbuff full"
        close_p2( p2 )
      end
    end

    ##
    # add p2 wbuff
    #
    def add_p2_wbuff( p2, data )
      return if p2.nil? || p2.closed?
      p2_info = @p2_infos[ p2 ]
      return if p2_info[ :closing ]
      p2_info[ :wbuff ] << data
      p2_info[ :last_recv_at ] = Time.new
      add_write( p2 )

      if p2_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        p1 = p2_info[ :p1 ]

        if p1 then
          p1_info = @p1_infos[ p1 ]

          if p1_info then
            puts "#{ Time.new } pause p1 #{ p1_info[ :im ].inspect } #{ p1_info[ :addrinfo ].inspect }"
            @reads.delete( p1 )
            p1_info[ :paused ] = true
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
    # close p1
    #
    def close_p1( p1 )
      return if p1.nil? || p1.closed?
      # puts "debug close p1"
      close_sock( p1 )
      @p1_infos.delete( p1 )
    end

    ##
    # close p1d
    #
    def close_p1d( p1d )
      return if p1d.nil? || p1d.closed?
      # puts "debug close p1d"
      close_sock( p1d )
      @p1d_infos.delete( p1d )
    end

    ##
    # close p2
    #
    def close_p2( p2 )
      return if p2.nil? || p2.closed?
      # puts "debug close p2"
      close_sock( p2 )
      p2_info = @p2_infos.delete( p2 )

      if p2_info then
        close_p1( p2_info[ :p1 ] )
      end
    end

    ##
    # close p2d
    #
    def close_p2d( p2d )
      return if p2d.nil? || p2d.closed?
      # puts "debug close p2d"
      close_sock( p2d )
      @p2d_infos.delete( p2d )
    end

    ##
    # close read p1
    #
    def close_read_p1( p1 )
      return if p1.nil? || p1.closed?
      # puts "debug close read p1"
      p1.close_read
      @reads.delete( p1 )

      if p1.closed? then
        # puts "debug p1 closed"
        @writes.delete( p1 )
        @roles.delete( p1 )
        @p1_infos.delete( p1 )
      end
    end

    ##
    # close read p2
    #
    def close_read_p2( p2 )
      return if p2.nil? || p2.closed?
      # puts "debug close read p2"
      p2.close_read
      @reads.delete( p2 )

      if p2.closed? then
        # puts "debug p2 closed"
        @writes.delete( p2 )
        @roles.delete( p2 )
        @p2_infos.delete( p2 )
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
    # close write p1
    #
    def close_write_p1( p1 )
      return if p1.nil? || p1.closed?
      # puts "debug close write p1"
      p1.close_write
      @writes.delete( p1 )

      if p1.closed? then
        # puts "debug p1 closed"
        @reads.delete( p1 )
        @roles.delete( p1 )
        @p1_infos.delete( p1 )
      end
    end

    ##
    # close write p2
    #
    def close_write_p2( p2 )
      return if p2.nil? || p2.closed?
      # puts "debug close write p2"
      p2.close_write
      @writes.delete( p2 )

      if p2.closed? then
        # puts "debug p2 closed"
        @reads.delete( p2 )
        @roles.delete( p2 )
        @p2_infos.delete( p2 )
      end
    end

    ##
    # del room info
    #
    def del_room_info( im )
      room_info = @room_infos.delete( im )

      if room_info then
        close_p1d( room_info[ :p1d ] )
        close_p2d( room_info[ :p2d ] )
      end
    end

    ##
    # loop check expire
    #
    def loop_check_expire
      Thread.new do
        loop do
          sleep CHECK_EXPIRE_INTERVAL
          now = Time.new

          @p2_infos.select{ | p2, _ | !p2.closed? }.values.each do | p2_info |
            last_recv_at = p2_info[ :last_recv_at ] || p2_info[ :created_at ]
            last_sent_at = p2_info[ :last_sent_at ] || p2_info[ :created_at ]
            is_expire = ( now - last_recv_at >= EXPIRE_AFTER ) && ( now - last_sent_at >= EXPIRE_AFTER )

            if is_expire then
              puts "#{ Time.new } expire p2 #{ p2_info[ :im ].inspect } #{ p2_info[ :addrinfo ].inspect }"
              p2_info[ :closing ] = true
              next_tick
            end
          end
        end
      end
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
    # new a listener
    #
    def new_a_listener( port, host )
      listener = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      listener.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
      listener.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )

      if RUBY_PLATFORM.include?( 'linux' ) then
        listener.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      end

      listener.bind( Socket.sockaddr_in( port, host ) )
      listener.listen( 127 )
      listener
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
    # new mirrords
    #
    def new_mirrords( begin_port )
      10.times do | i |
        mirrord_port = begin_port + i
        mirrord = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
        mirrord.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
        mirrord.bind( Socket.sockaddr_in( mirrord_port, '0.0.0.0' ) )
        puts "#{ Time.new } mirrord bind on #{ mirrord_port }"
        add_read( mirrord, :mirrord )
      end
    end

    ##
    # next tick
    #
    def next_tick
      @dotw.write( '.' )
    end

    ##
    # send data
    #
    def send_data( sock, data, target_addr )
      begin
        sock.sendmsg_nonblock( data, 0, target_addr )
      rescue Exception => e
        puts "#{ Time.new } sendmsg #{ e.class }"
      end
    end

    ##
    # set p1 closing write
    #
    def set_p1_closing_write( p1 )
      return if p1.nil? || p1.closed?
      p1_info = @p1_infos[ p1 ]
      return if p1_info[ :closing_write ]
      # puts "debug set p1 closing write"
      p1_info[ :closing_write ] = true
      add_write( p1 )
    end

    ##
    # set p2 closing write
    #
    def set_p2_closing_write( p2 )
      return if p2.nil? || p2.closed?
      p2_info = @p2_infos[ p2 ]
      return if p2_info[ :closing_write ]
      # puts "debug set p2 closing write"
      p2_info[ :closing_write ] = true
      add_write( p2 )
    end

    ##
    # set p2d ports
    #
    def set_p2d_ports( p2d_ports )
      @p2d_ports = {}

      p2d_ports.each do | im, p2d_port |
        @p2d_ports[ im ] = p2d_port
      end
    end

    ##
    # read dotr
    #
    def read_dotr( dotr )
      dotr.read_nonblock( READ_SIZE )
      @p2_infos.select{ | _, info | info[ :closing ] }.keys.each{ | p2 | close_p2( p2 ) }
    end

    ##
    # read mirrord
    #
    def read_mirrord( mirrord )
      data, addrinfo, rflags, *controls = mirrord.recvmsg
      return if data.empty? || ( data.size > ROOM_TITLE_LIMIT ) || data =~ /\r|\n/

      im = data
      room_info = @room_infos[ im ]

      if room_info then
        room_info[ :mirrord ] = mirrord
        room_info[ :p1_addrinfo ] = addrinfo
        room_info[ :updated_at ] = Time.new
      elsif @p2d_ports.include?( im ) then
        p2d_port = @p2d_ports[ im ]
        p1d = new_a_listener( 0, '0.0.0.0' )
        p2d = new_a_listener( p2d_port, @p2d_host )
        print "#{ Time.new } p1d listen on #{ p1d.local_address.inspect }"
        puts " p2d listen on #{ p2d.local_address.inspect }"

        @p1d_infos[ p1d ] = {
          im: im
        }

        @p2d_infos[ p2d ] = {
          im: im
        }

        @room_infos[ im ] = {
          mirrord: mirrord,
          p1_addrinfo: addrinfo,
          updated_at: Time.new,
          p1d: p1d,
          p2d: p2d
        }

        add_read( p1d, :p1d )
        add_read( p2d, :p2d )
      else
        puts "#{ Time.new } unknown room #{ im.inspect }"
      end
    end

    ##
    # read infod
    #
    def read_infod( infod )
      data, addrinfo, rflags, *controls = infod.recvmsg
      return if data.empty?

      data2 = @room_infos.sort_by{ | _, info | info[ :updated_at ] }.reverse.map do | im, info |
        [
          info[ :updated_at ],
          @p2d_ports[ im ],
          im + ' ' * ( ROOM_TITLE_LIMIT - im.size ),
          info[ :p1_addrinfo ].ip_unpack.join( ':' )
        ].join( ' ' )
      end.join( "\n" )

      send_data( infod, data2, addrinfo )
    end

    ##
    # read p1d
    #
    def read_p1d( p1d )
      if p1d.closed? then
        puts "#{ Time.new } read p1d but p1d closed?"
        return
      end

      p1d_info = @p1d_infos[ p1d ]
      im = p1d_info[ :im ]

      begin
        p1, addrinfo = p1d.accept_nonblock
      rescue Exception => e
        puts "#{ Time.new } p1d accept #{ e.class } #{ im.inspect }"
        del_room_info( im )
        return
      end

      @p1_infos[ p1 ] = {
        addrinfo: addrinfo,   # 地址
        im: im,               # 标识
        p2: nil,              # 对应p2
        wbuff: '',            # 写前
        closing_write: false, # 准备关闭写
        paused: false         # 是否暂停
      }

      add_read( p1, :p1 )
      puts "#{ Time.new } here comes a p1 #{ im.inspect } #{ addrinfo.inspect }"
    end

    ##
    # read p2d
    #
    def read_p2d( p2d )
      if p2d.closed? then
        puts "#{ Time.new } read p2d but p2d closed?"
        return
      end

      p2d_info = @p2d_infos[ p2d ]
      im = p2d_info[ :im ]

      begin
        p2, addrinfo = p2d.accept_nonblock
      rescue Exception => e
        puts "#{ Time.new } p2d accept #{ e.class } #{ im.inspect }"
        del_room_info( im )
        return
      end

      room_info = @room_infos[ im ]
      p1d_port = room_info[ :p1d ].local_address.ip_port
      p2_id = rand( ( 2 ** 64 ) - 2 ) + 1

      @p2_infos[ p2 ] = {
        p2_id: p2_id,         # p2 id
        addrinfo: addrinfo,   # 地址
        im: im,               # 标识
        p1: nil,              # 对应p1
        rbuff: '',            # 匹配到p1之前，暂存流量
        wbuff: '',            # 写前
        created_at: Time.new, # 创建时间
        last_recv_at: nil,    # 上一次收到流量（p1读到，放入p2写前）的时间
        last_sent_at: nil,    # 上一次中转流量（p1写）的时间
        closing: false,       # 是否准备关闭
        closing_write: false, # 准备关闭写
        paused: false         # 是否暂停
      }

      add_read( p2, :p2 )

      puts "#{ Time.new } here comes a p2 #{ im.inspect } #{ addrinfo.inspect } #{ p2_id }"
      puts "rooms #{ @room_infos.size } p1ds #{ @p1d_infos.size } p2ds #{ @p2d_infos.size } p1s #{ @p1_infos.size } p2s #{ @p2_infos.size }"
      data = [ p1d_port, p2_id ].pack( 'nQ>' )
      send_data( room_info[ :mirrord ], data, room_info[ :p1_addrinfo ] )
    end

    ##
    # read p1
    #
    def read_p1( p1 )
      if p1.closed? then
        puts "#{ Time.new } read p1 but p1 closed?"
        return
      end

      p1_info = @p1_infos[ p1 ]
      p2 = p1_info[ :p2 ]

      begin
        data = p1.read_nonblock( READ_SIZE )
      rescue Exception => e
        # puts "debug read p1 #{ e.class }"
        close_read_p1( p1 )
        set_p2_closing_write( p2 )
        return
      end

      unless p2 then
        if data.bytesize < 8 then
          puts "#{ Time.new } read p1 miss p2 id? #{ data.inspect }"
          close_p1( p1 )
          return
        end

        p2_id = data[ 0, 8 ].unpack( 'Q>' ).first
        p2, p2_info = @p2_infos.find{ | _, info | ( info[ :p2_id ] == p2_id ) && info[ :p1 ].nil? }

        unless p2 then
          # puts "debug p2 not found #{ p2_id }"
          close_p1( p1 )
          return
        end

        puts "#{ Time.new } paired #{ p1_info[ :im ].inspect } #{ p1_info[ :addrinfo ].inspect } #{ p2_info[ :addrinfo ].inspect } #{ p2_id }"
        p1_info[ :p2 ] = p2
        p1_info[ :wbuff ] << p2_info[ :rbuff ]

        unless p1_info[ :wbuff ].empty? then
          add_write( p1 )
        end

        p2_info[ :p1 ] = p1
        data = data[ 8..-1 ]

        if data.empty? then
          return
        end
      end

      add_p2_wbuff( p2, data )
    end

    ##
    # read p2
    #
    def read_p2( p2 )
      if p2.closed? then
        puts "#{ Time.new } read p2 but p2 closed?"
        return
      end

      p2_info = @p2_infos[ p2 ]
      p1 = p2_info[ :p1 ]

      begin
        data = p2.read_nonblock( READ_SIZE )
      rescue Exception => e
        # puts "debug read p2 #{ e.class }"
        close_read_p2( p2 )
        set_p1_closing_write( p1 )
        return
      end

      if p1 then
        add_p1_wbuff( p1, data )
      else
        add_p2_rbuff( p2, data )
      end
    end

    ##
    # write p1
    #
    def write_p1( p1 )
      if p1.closed? then
        puts "#{ Time.new } write p1 but p1 closed?"
        return
      end

      p1_info = @p1_infos[ p1 ]
      p2 = p1_info[ :p2 ]
      data = p1_info[ :wbuff ]

      # 写前为空，处理关闭写
      if data.empty? then
        if p1_info[ :closing_write ] then
          close_write_p1( p1 )
        else
          @writes.delete( p1 )
        end

        return
      end

      # 写入
      begin
        written = p1.write_nonblock( data )
      rescue Exception => e
        # puts "debug write p1 #{ e.class }"
        close_write_p1( p1 )
        close_read_p2( p2 )
        return
      end

      data = data[ written..-1 ]
      p1_info[ :wbuff ] = data

      if p2 && !p2.closed? then
        p2_info = @p2_infos[ p2 ]

        if p2_info[ :paused ] && ( p1_info[ :wbuff ].bytesize < RESUME_BELOW ) then
          puts "#{ Time.new } resume p2 #{ p2_info[ :im ].inspect } #{ p2_info[ :addrinfo ].inspect }"
          add_read( p2 )
          p2_info[ :paused ] = false
        end

        p2_info[ :last_sent_at ] = Time.new
      end
    end

    ##
    # write p2
    #
    def write_p2( p2 )
      if p2.closed? then
        puts "#{ Time.new } write p2 but p2 closed?"
        return
      end

      p2_info = @p2_infos[ p2 ]
      p1 = p2_info[ :p1 ]
      data = p2_info[ :wbuff ]

      # 写前为空，处理关闭写
      if data.empty? then
        if p2_info[ :closing_write ] then
          close_write_p2( p2 )
        else
          @writes.delete( p2 )
        end

        return
      end

      # 写入
      begin
        written = p2.write_nonblock( data )
      rescue Exception => e
        # puts "debug write p2 #{ e.class }"
        close_write_p2( p2 )
        close_read_p1( p1 )
        return
      end

      data = data[ written..-1 ]
      p2_info[ :wbuff ] = data

      if p1 && !p1.closed? then
        p1_info = @p1_infos[ p1 ]

        if p1_info[ :paused ] && ( p2_info[ :wbuff ].bytesize < RESUME_BELOW ) then
          puts "#{ Time.new } resume p1 #{ p1_info[ :im ].inspect } #{ p1_info[ :addrinfo ].inspect }"
          add_read( p1 )
          p1_info[ :paused ] = false
        end
      end
    end
  end
end
