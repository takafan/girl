module Girl
  class RelayWorker
    include Custom

    def initialize( relay_proxyd_port, relay_girl_port, proxyd_host, proxyd_port, girl_port )
      @proxyd_addr = Socket.sockaddr_in( proxyd_port, proxyd_host )
      @girl_addr = Socket.sockaddr_in( girl_port, proxyd_host )
      @update_roles = [ :relay_tcp, :relay_tun, :tcp, :tun ] # 参与淘汰的角色
      @updates_limit = 1008 # 淘汰池上限，1015(mac) - 1 (pair) - [ girlc, info, infod, relay_girl, relay_tcpd, relay_tund ]
      @reads = []           # 读池
      @writes = []          # 写池
      @updates = {}         # sock => updated_at
      @eliminate_count = 0  # 淘汰次数
      @roles = {}           # sock => :infod / :relay_girl / :relay_tcp / :relay_tcpd / :relay_tun / :relay_tund / :tcp / :tun
      @relay_tcp_infos = {} # relay_tcp => { :wbuff :closing }
      @relay_tun_infos = {} # relay_tun => { :wbuff :closing :paused }
      @tcp_infos = {}       # tcp => { :wbuff :closing }
      @tun_infos = {}       # tun => { :wbuff :closing :paused }

      new_a_relay_tcpd( relay_proxyd_port )
      new_a_infod( relay_proxyd_port )
      new_a_relay_tund( relay_girl_port )
      new_a_relay_girl( relay_girl_port )
      new_a_girlc
    end

    def looping
      # puts "#{ Time.new } looping"
      loop_check_expire

      loop do
        rs, ws = IO.select( @reads, @writes )

        rs.each do | sock |
          role = @roles[ sock ]

          case role
          when :infod then
            read_infod( sock )
          when :relay_girl then
            read_relay_girl( sock )
          when :relay_tcp then
            read_relay_tcp( sock )
          when :relay_tcpd then
            read_relay_tcpd( sock )
          when :relay_tun then
            read_relay_tun( sock )
          when :relay_tund then
            read_relay_tund( sock )
          when :tcp then
            read_tcp( sock )
          when :tun then
            read_tun( sock )
          else
            # puts "debug read unknown role #{ role }"
            close_sock( sock )
          end
        end

        ws.each do | sock |
          role = @roles[ sock ]

          case role
          when :relay_tcp then
            write_relay_tcp( sock )
          when :relay_tun then
            write_relay_tun( sock )
          when :tcp then
            write_tcp( sock )
          when :tun then
            write_tun( sock )
          else
            # puts "debug write unknown role #{ role }"
            close_sock( sock )
          end
        end
      end
    rescue Interrupt => e
      # puts e.class
      quit!
    end

    def quit!
      # puts "debug exit"
      exit
    end

    private

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

    def add_relay_tcp_wbuff( relay_tcp, data )
      return if relay_tcp.nil? || relay_tcp.closed? || data.empty?
      relay_tcp_info = @relay_tcp_infos[ relay_tcp ]
      relay_tcp_info[ :wbuff ] << data
      add_write( relay_tcp )
    end

    def add_relay_tun_wbuff( relay_tun, data )
      return if relay_tun.nil? || relay_tun.closed? || data.empty?
      relay_tun_info = @relay_tun_infos[ relay_tun ]
      relay_tun_info[ :wbuff ] << data
      add_write( relay_tun )
      return if relay_tun.closed?

      if relay_tun_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        tun = relay_tun_info[ :tun ]

        if tun then
          tun_info = @tun_infos[ tun ]

          if tun_info then
            # puts "#{ Time.new } pause tun"
            @reads.delete( tun )
            tun_info[ :paused ] = true
          end
        end
      end
    end

    def add_tcp_wbuff( tcp, data )
      return if tcp.nil? || tcp.closed? || data.empty?
      tcp_info = @tcp_infos[ tcp ]
      tcp_info[ :wbuff ] << data
      add_write( tcp )
    end

    def add_tun_wbuff( tun, data )
      return if tun.nil? || tun.closed? || data.empty?
      tun_info = @tun_infos[ tun ]
      tun_info[ :wbuff ] << data
      add_write( tun )
      return if tun.closed?

      if tun_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        relay_tun = tun_info[ :relay_tun ]

        if relay_tun then
          relay_tun_info = @relay_tun_infos[ relay_tun ]

          if relay_tun_info then
            # puts "#{ Time.new } pause relay tun"
            @reads.delete( relay_tun )
            relay_tun_info[ :paused ] = true
          end
        end
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

    def close_relay_tcp( relay_tcp )
      return nil if relay_tcp.nil? || relay_tcp.closed?
      # puts "debug close relay tcp"
      close_sock( relay_tcp )
      relay_tcp_info = @relay_tcp_infos.delete( relay_tcp )
      set_tcp_closing( relay_tcp_info[ :tcp ] ) if relay_tcp_info
      relay_tcp_info
    end

    def close_relay_tun( relay_tun )
      return nil if relay_tun.nil? || relay_tun.closed?
      # puts "debug close relay tun"
      close_sock( relay_tun )
      relay_tun_info = @relay_tun_infos.delete( relay_tun )
      set_tun_closing( relay_tun_info[ :tun ] ) if relay_tun_info
      relay_tun_info
    end

    def close_sock( sock )
      return if sock.nil? || sock.closed?
      sock.close
      @reads.delete( sock )
      @writes.delete( sock )
      @updates.delete( sock )
      @roles.delete( sock )
    end

    def close_tcp( tcp )
      return nil if tcp.nil? || tcp.closed?
      # puts "debug close tcp"
      close_sock( tcp )
      tcp_info = @tcp_infos.delete( tcp )
      set_relay_tcp_closing( tcp_info[ :relay_tcp ] ) if tcp_info
      tcp_info
    end

    def close_tun( tun )
      return nil if tun.nil? || tun.closed?
      # puts "debug close tun"
      close_sock( tun )
      tun_info = @tun_infos.delete( tun )
      set_relay_tun_closing( tun_info[ :relay_tun ] ) if tun_info
      tun_info
    end

    def loop_check_expire
      Thread.new do
        loop do
          sleep CHECK_EXPIRE_INTERVAL

          msg = {
            message_type: 'check-expire'
          }

          send_data( @info, JSON.generate( msg ), @infod_addr )
        end
      end
    end

    def new_a_girlc
      girlc = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      @girlc = girlc
    end

    def new_a_relay_girl( relay_girl_port )
      relay_girl_addr = Socket.sockaddr_in( relay_girl_port, '0.0.0.0' )
      relay_girl = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      relay_girl.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 ) if RUBY_PLATFORM.include?( 'linux' )
      relay_girl.bind( relay_girl_addr )
      # puts "#{ Time.new } relay girl bind on #{ relay_girl_port }"
      add_read( relay_girl, :relay_girl )
    end

    def new_a_infod( infod_port )
      infod_addr = Socket.sockaddr_in( infod_port, '127.0.0.1' )
      infod = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      infod.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 ) if RUBY_PLATFORM.include?( 'linux' )
      infod.bind( infod_addr )
      # puts "#{ Time.new } infod bind on #{ infod_port }"
      add_read( infod, :infod )
      info = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      @infod_addr = infod_addr
      @infod = infod
      @info = info
    end

    def new_a_relay_tcpd( relay_tcpd_port )
      relay_tcpd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      relay_tcpd.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
      relay_tcpd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 ) if RUBY_PLATFORM.include?( 'linux' )
      relay_tcpd.bind( Socket.sockaddr_in( relay_tcpd_port, '0.0.0.0' ) )
      relay_tcpd.listen( BACKLOG )
      # puts "#{ Time.new } relay tcpd listen on #{ relay_tcpd_port }"
      add_read( relay_tcpd, :relay_tcpd )
    end

    def new_a_relay_tund( relay_girl_port )
      relay_tund = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      relay_tund.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
      relay_tund.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 ) if RUBY_PLATFORM.include?( 'linux' )
      relay_tund.bind( Socket.sockaddr_in( relay_girl_port, '0.0.0.0' ) )
      relay_tund.listen( BACKLOG )
      # puts "#{ Time.new } relay tund listen on #{ relay_girl_port }"
      add_read( relay_tund, :relay_tund )
    end

    def read_infod( infod )
      begin
        data, addrinfo, rflags, *controls = infod.recvmsg
      rescue Exception => e
        puts "#{ Time.new } infod recvmsg #{ e.class }"
        return
      end

      return if data.empty?

      begin
        msg = JSON.parse( data, symbolize_names: true )
      rescue JSON::ParserError, EncodingError => e
        puts "#{ Time.new } read infod #{ e.class }"
        return
      end

      message_type = msg[ :message_type ]

      case message_type
      when 'check-expire' then
        now = Time.new
        socks = @updates.select{ | _, updated_at | now - updated_at >= EXPIRE_AFTER }.keys

        if socks.any? then
          relay_tcp_count = relay_tun_count = tcp_count = tun_count = 0

          socks.each do | sock |
            case @roles[ sock ]
            when :relay_tcp
              close_relay_tcp( sock )
              relay_tcp_count += 1
            when :relay_tun
              close_relay_tun( sock )
              relay_tun_count += 1
            when :tcp
              close_tcp( sock )
              tcp_count += 1
            when :tun
              close_tun( sock )
              tun_count += 1
            else
              close_sock( sock )
            end
          end

          # puts "#{ now } expire relay tcp #{ relay_tcp_count } relay tun #{ relay_tun_count } tcp #{ tcp_count } tun #{ tun_count }"
        end
      when 'memory-info' then
        msg2 = {
          sizes: {
            updates: @updates.size,
            relay_tcp_infos: @relay_tcp_infos.size,
            relay_tun_infos: @relay_tun_infos.size,
            tcp_infos: @tcp_infos.size,
            tun_infos: @tun_infos.size
          },
          updates_limit: @updates_limit,
          eliminate_count: @eliminate_count
        }

        send_data( @infod, JSON.generate( msg2 ), addrinfo )
      end
    end

    def read_relay_girl( relay_girl )
      begin
        data, addrinfo, rflags, *controls = relay_girl.recvmsg
      rescue Exception => e
        puts "#{ Time.new } relay girl recvmsg #{ e.class }"
        return
      end

      return if data.empty?
      send_data( @girlc, data, @girl_addr )
    end

    def read_relay_tcp( relay_tcp )
      begin
        data = relay_tcp.read_nonblock( READ_SIZE )
      rescue Exception => e
        # puts "debug read relay tcp #{ e.class }"
        close_relay_tcp( relay_tcp )
        return
      end

      set_update( relay_tcp )
      relay_tcp_info = @relay_tcp_infos[ relay_tcp ]
      tcp = relay_tcp_info[ :tcp ]
      add_tcp_wbuff( tcp, data )
    end

    def read_relay_tcpd( relay_tcpd )
      begin
        relay_tcp, addrinfo = relay_tcpd.accept_nonblock
      rescue Exception => e
        puts "#{ Time.new } relay tcpd accept #{ e.class }"
        return
      end

      tcp = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      tcp.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )

      begin
        tcp.connect_nonblock( @proxyd_addr )
      rescue IO::WaitWritable
      rescue Exception => e
        puts "#{ Time.new } connect tcpd #{ e.class }"
        tcp.close
        relay_tcp.close
        return
      end

      @relay_tcp_infos[ relay_tcp ] = {
        wbuff: '',
        closing: false,
        tcp: tcp
      }

      @tcp_infos[ tcp ] = {
        wbuff: '',
        closing: false,
        relay_tcp: relay_tcp
      }

      add_read( relay_tcp, :relay_tcp )
      add_read( tcp, :tcp )
    end

    def read_relay_tun( relay_tun )
      begin
        data = relay_tun.read_nonblock( READ_SIZE )
      rescue Exception => e
        # puts "debug read relay tun #{ e.class }"
        close_relay_tun( relay_tun )
        return
      end

      set_update( relay_tun )
      relay_tun_info = @relay_tun_infos[ relay_tun ]
      tun = relay_tun_info[ :tun ]
      add_tun_wbuff( tun, data )
    end

    def read_relay_tund( relay_tund )
      begin
        relay_tun, addrinfo = relay_tund.accept_nonblock
      rescue Exception => e
        puts "#{ Time.new } relay tund accept #{ e.class }"
        return
      end

      tun = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      tun.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )

      begin
        tun.connect_nonblock( @girl_addr )
      rescue IO::WaitWritable
      rescue Exception => e
        puts "#{ Time.new } connect tund #{ e.class }"
        tun.close
        relay_tun.close
        return
      end

      @relay_tun_infos[ relay_tun ] = {
        wbuff: '',
        closing: false,
        paused: false,
        tun: tun
      }

      @tun_infos[ tun ] = {
        wbuff: '',
        closing: false,
        paused: false,
        relay_tun: relay_tun
      }

      add_read( relay_tun, :relay_tun )
      add_read( tun, :tun )
    end

    def read_tcp( tcp )
      begin
        data = tcp.read_nonblock( READ_SIZE )
      rescue Exception => e
        # puts "debug read tcp #{ e.class }"
        close_tcp( tcp )
        return
      end

      set_update( tcp )
      tcp_info = @tcp_infos[ tcp ]
      relay_tcp = tcp_info[ :relay_tcp ]
      add_relay_tcp_wbuff( relay_tcp, data )
    end

    def read_tun( tun )
      begin
        data = tun.read_nonblock( READ_SIZE )
      rescue Exception => e
        # puts "debug read tun #{ e.class }"
        close_tun( tun )
        return
      end

      set_update( tun )
      tun_info = @tun_infos[ tun ]
      relay_tun = tun_info[ :relay_tun ]
      add_relay_tun_wbuff( relay_tun, data )
    end

    def send_data( sock, data, target_addr )
      begin
        sock.sendmsg( data, 0, target_addr )
      rescue Exception => e
        puts "#{ Time.new } sendmsg #{ e.class }"
      end
    end

    def set_relay_tcp_closing( relay_tcp )
      return if relay_tcp.nil? || relay_tcp.closed?
      relay_tcp_info = @relay_tcp_infos[ relay_tcp ]
      return if relay_tcp_info.nil? || relay_tcp_info[ :closing ]
      relay_tcp_info[ :closing ] = true
      add_write( relay_tcp )
    end

    def set_relay_tun_closing( relay_tun )
      return if relay_tun.nil? || relay_tun.closed?
      relay_tun_info = @relay_tun_infos[ relay_tun ]
      return if relay_tun_info.nil? || relay_tun_info[ :closing ]
      relay_tun_info[ :closing ] = true
      add_write( relay_tun )
    end

    def set_tcp_closing( tcp )
      return if tcp.nil? || tcp.closed?
      tcp_info = @tcp_infos[ tcp ]
      return if tcp_info.nil? || tcp_info[ :closing ]
      tcp_info[ :closing ] = true
      add_write( tcp )
    end

    def set_tun_closing( tun )
      return if tun.nil? || tun.closed?
      tun_info = @tun_infos[ tun ]
      return if tun_info.nil? || tun_info[ :closing ]
      tun_info[ :closing ] = true
      add_write( tun )
    end

    def set_update( sock )
      @updates[ sock ] = Time.new

      if @updates_limit - @updates.size <= 20 then
        puts "updates #{ @updates.size }"
      end

      if @updates.size >= @updates_limit then
        puts "#{ Time.new } eliminate updates"

        @updates.keys.each do | _sock |
          case @roles[ _sock ]
          when :relay_tcp
            close_relay_tcp( _sock )
          when :relay_tun
            close_relay_tun( _sock )
          when :tcp
            close_tcp( _sock )
          when :tun
            close_tun( _sock )
          else
            close_sock( _sock )
          end
        end

        @eliminate_count += 1
      end
    end

    def write_relay_tcp( relay_tcp )
      if relay_tcp.closed? then
        puts "#{ Time.new } write closed relay tcp?"
        return
      end

      relay_tcp_info = @relay_tcp_infos[ relay_tcp ]
      data = relay_tcp_info[ :wbuff ]

      if data.empty? then
        if relay_tcp_info[ :closing ] then
          close_relay_tcp( relay_tcp )
        else
          @writes.delete( relay_tcp )
        end

        return
      end

      begin
        written = relay_tcp.write_nonblock( data )
      rescue Exception => e
        # puts "debug write relay tcp #{ e.class }"
        close_relay_tcp( relay_tcp )
        return
      end

      set_update( relay_tcp )
      data = data[ written..-1 ]
      relay_tcp_info[ :wbuff ] = data
    end

    def write_relay_tun( relay_tun )
      if relay_tun.closed? then
        puts "#{ Time.new } write closed relay tun?"
        return
      end

      relay_tun_info = @relay_tun_infos[ relay_tun ]
      data = relay_tun_info[ :wbuff ]

      if data.empty? then
        if relay_tun_info[ :closing ] then
          close_relay_tun( relay_tun )
        else
          @writes.delete( relay_tun )
        end

        return
      end

      begin
        written = relay_tun.write_nonblock( data )
      rescue Exception => e
        # puts "debug write relay tun #{ e.class }"
        close_relay_tun( relay_tun )
        return
      end

      set_update( relay_tun )
      data = data[ written..-1 ]
      relay_tun_info[ :wbuff ] = data
      tun = relay_tun_info[ :tun ]

      if tun && !tun.closed? then
        tun_info = @tun_infos[ tun ]

        if tun_info[ :paused ] && ( relay_tun_info[ :wbuff ].bytesize < RESUME_BELOW ) then
          # puts "#{ Time.new } resume tun"
          add_read( tun )
          tun_info[ :paused ] = false unless tun.closed?
        end
      end
    end

    def write_tcp( tcp )
      if tcp.closed? then
        puts "#{ Time.new } write closed tcp?"
        return
      end

      tcp_info = @tcp_infos[ tcp ]
      data = tcp_info[ :wbuff ]

      if data.empty? then
        if tcp_info[ :closing ] then
          close_tcp( tcp )
        else
          @writes.delete( tcp )
        end

        return
      end

      begin
        written = tcp.write_nonblock( data )
      rescue Exception => e
        # puts "debug write tcp #{ e.class }"
        close_tcp( tcp )
        return
      end

      set_update( tcp )
      data = data[ written..-1 ]
      tcp_info[ :wbuff ] = data
    end

    def write_tun( tun )
      if tun.closed? then
        puts "#{ Time.new } write closed tun?"
        return
      end

      tun_info = @tun_infos[ tun ]
      data = tun_info[ :wbuff ]

      if data.empty? then
        if tun_info[ :closing ] then
          close_tun( tun )
        else
          @writes.delete( tun )
        end

        return
      end

      begin
        written = tun.write_nonblock( data )
      rescue Exception => e
        # puts "debug write tun #{ e.class }"
        close_tun( tun )
        return
      end

      set_update( tun )
      data = data[ written..-1 ]
      tun_info[ :wbuff ] = data
      relay_tun = tun_info[ :relay_tun ]

      if relay_tun && !relay_tun.closed? then
        relay_tun_info = @relay_tun_infos[ relay_tun ]

        if relay_tun_info[ :paused ] && ( tun_info[ :wbuff ].bytesize < RESUME_BELOW ) then
          # puts "#{ Time.new } resume relay tun"
          add_read( relay_tun )
          relay_tun_info[ :paused ] = false unless relay_tun.closed?
        end
      end
    end

  end
end
