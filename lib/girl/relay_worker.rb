module Girl
  class RelayWorker
    include Custom

    def initialize( relay_proxyd_port, relay_girl_port, proxyd_host, proxyd_port, girl_port )
      @reads = []
      @writes = []
      @roles = {}           # sock => :infod / :relay_girl / :relay_tcp / :relay_tcpd / :relay_tun / :relay_tund / :tcp / :tun
      @relay_tcp_infos = {} # relay_tcp => { :wbuff, :created_at, :last_recv_at }
      @relay_tun_infos = {} # relay_tun => { :wbuff, :created_at, :last_add_wbuff_at, :paused }
      @tcp_infos = {}       # tcp => { :wbuff, :created_at, :last_recv_at }
      @tun_infos = {}       # tun => { :wbuff, :created_at, :last_add_wbuff_at, :paused }
      @proxyd_addr = Socket.sockaddr_in( proxyd_port, proxyd_host )
      @girl_addr = Socket.sockaddr_in( girl_port, proxyd_host )
      
      new_a_relay_tcpd( relay_proxyd_port )
      new_a_infod( relay_proxyd_port )
      new_a_relay_tund( relay_girl_port )
      new_a_relay_girl( relay_girl_port )
      new_a_girlc
    end

    def looping
      puts "#{ Time.new } looping"
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
            puts "#{ Time.new } read unknown role #{ role }"
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
            puts "#{ Time.new } write unknown role #{ role }"
            close_sock( sock )
          end
        end
      end
    rescue Interrupt => e
      puts e.class
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
      end
    end

    def add_relay_tcp_wbuff( relay_tcp, data )
      return if relay_tcp.nil? || relay_tcp.closed?
      relay_tcp_info = @relay_tcp_infos[ relay_tcp ]
      relay_tcp_info[ :wbuff ] << data
      add_write( relay_tcp )
    end

    def add_relay_tun_wbuff( relay_tun, data )
      return if relay_tun.nil? || relay_tun.closed?
      relay_tun_info = @relay_tun_infos[ relay_tun ]
      relay_tun_info[ :wbuff ] << data
      add_write( relay_tun )

      if relay_tun_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        tun = relay_tun_info[ :tun ]

        if tun then
          tun_info = @tun_infos[ tun ]

          if tun_info then
            puts "#{ Time.new } pause tun"
            @reads.delete( tun )
            tun_info[ :paused ] = true
          end
        end
      end
    end

    def add_tcp_wbuff( tcp, data )
      return if tcp.nil? || tcp.closed?
      tcp_info = @tcp_infos[ tcp ]
      tcp_info[ :wbuff ] << data
      add_write( tcp )
    end

    def add_tun_wbuff( tun, data )
      return if tun.nil? || tun.closed?
      tun_info = @tun_infos[ tun ]
      tun_info[ :wbuff ] << data
      tun_info[ :last_add_wbuff_at ] = Time.new
      add_write( tun )

      if tun_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        relay_tun = tun_info[ :relay_tun ]

        if relay_tun then
          relay_tun_info = @relay_tun_infos[ relay_tun ]

          if relay_tun_info then
            puts "#{ Time.new } pause relay tun"
            @reads.delete( relay_tun )
            relay_tun_info[ :paused ] = true
          end
        end
      end
    end

    def add_write( sock )
      return if sock.nil? || sock.closed? || @writes.include?( sock )
      @writes << sock
    end

    def close_read_relay_tun( relay_tun )
      return if relay_tun.nil? || relay_tun.closed?
      # puts "debug close read relay tun"
      relay_tun.close_read
      @reads.delete( relay_tun )

      if relay_tun.closed? then
        # puts "debug relay tun closed"
        @writes.delete( relay_tun )
        @roles.delete( relay_tun )
        @relay_tun_infos.delete( relay_tun )
      end
    end

    def close_read_tun( tun )
      return if tun.nil? || tun.closed?
      # puts "debug close read tun"
      tun.close_read
      @reads.delete( tun )

      if tun.closed? then
        # puts "debug tun closed"
        @writes.delete( tun )
        @roles.delete( tun )
        @tun_infos.delete( tun )
      end
    end

    def close_relay_tcp( relay_tcp )
      return if relay_tcp.nil? || relay_tcp.closed?
      # puts "debug close relay tcp"
      close_sock( relay_tcp )
      @relay_tcp_infos.delete( relay_tcp )
    end

    def close_relay_tun( relay_tun )
      return if relay_tun.nil? || relay_tun.closed?
      # puts "debug close relay tun"
      close_sock( relay_tun )
      @relay_tun_infos.delete( relay_tun )
    end

    def close_sock( sock )
      return if sock.nil? || sock.closed?
      sock.close
      @reads.delete( sock )
      @writes.delete( sock )
      @roles.delete( sock )
    end

    def close_tcp( tcp )
      return if tcp.nil? || tcp.closed?
      # puts "debug close tcp"
      close_sock( tcp )
      @tcp_infos.delete( tcp )
    end

    def close_tun( tun )
      return if tun.nil? || tun.closed?
      # puts "debug close tun"
      close_sock( tun )
      @tun_infos.delete( tun )
    end

    def close_write_relay_tun( relay_tun )
      return if relay_tun.nil? || relay_tun.closed?
      # puts "debug close write relay tun"
      relay_tun.close_write
      @writes.delete( relay_tun )

      if relay_tun.closed? then
        # puts "debug relay tun closed"
        @reads.delete( relay_tun )
        @roles.delete( relay_tun )
        @relay_tun_infos.delete( relay_tun )
      end
    end

    def close_write_tun( tun )
      return if tun.nil? || tun.closed?
      # puts "debug close write tun"
      tun.close_write
      @writes.delete( tun )

      if tun.closed? then
        # puts "debug tun closed"
        @reads.delete( tun )
        @roles.delete( tun )
        @tun_infos.delete( tun )
      end
    end

    def loop_check_expire
      Thread.new do
        loop do
          sleep CHECK_EXPIRE_INTERVAL

          msg = {
            message_type: 'check-expire'
          }

          send_msg_to_infod( msg )
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
      relay_girl.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      relay_girl.bind( relay_girl_addr )
      puts "#{ Time.new } relay girl bind on #{ relay_girl_port }"
      add_read( relay_girl, :relay_girl )
    end

    def new_a_infod( infod_port )
      infod_addr = Socket.sockaddr_in( infod_port, '127.0.0.1' )
      infod = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      infod.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      infod.bind( infod_addr )
      puts "#{ Time.new } infod bind on #{ infod_port }"
      add_read( infod, :infod )
      info = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      @infod_addr = infod_addr
      @infod = infod
      @info = info
    end

    def new_a_relay_tcpd( relay_tcpd_port )
      relay_tcpd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      relay_tcpd.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
      relay_tcpd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      relay_tcpd.bind( Socket.sockaddr_in( relay_tcpd_port, '0.0.0.0' ) )
      relay_tcpd.listen( 127 )
      puts "#{ Time.new } relay tcpd listen on #{ relay_tcpd_port }"
      add_read( relay_tcpd, :relay_tcpd )
    end

    def new_a_relay_tund( relay_girl_port )
      relay_tund = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      relay_tund.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )
      relay_tund.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      relay_tund.bind( Socket.sockaddr_in( relay_girl_port, '0.0.0.0' ) )
      relay_tund.listen( 127 )
      puts "#{ Time.new } relay tund listen on #{ relay_girl_port }"
      add_read( relay_tund, :relay_tund )
    end

    def read_infod( infod )
      data, addrinfo, rflags, *controls = infod.recvmsg
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

        @tcp_infos.select{ | _, _tcp_info | now - ( _tcp_info[ :last_recv_at ] || _tcp_info[ :created_at ] ) >= EXPIRE_AFTER }.keys.each do | tcp |
          puts "#{ Time.new } expire tcp #{ tcp.object_id }"
          close_tcp( tcp )
        end

        @relay_tcp_infos.select{ | _, _relay_tcp_info | now - ( _relay_tcp_info[ :last_recv_at ] || _relay_tcp_info[ :created_at ] ) >= EXPIRE_AFTER }.keys.each do | relay_tcp |
          puts "#{ Time.new } expire relay tcp #{ relay_tcp.object_id }"
          close_relay_tcp( relay_tcp )
        end

        @tun_infos.select{ | _, _tun_info | now - ( _tun_info[ :last_add_wbuff_at ] || _tun_info[ :created_at ] ) >= EXPIRE_AFTER }.keys.each do | tun |
          puts "#{ Time.new } expire tun #{ tun.object_id }"
          close_tun( tun )
        end

        @relay_tun_infos.select{ | _, _relay_tun_info | now - ( _relay_tun_info[ :last_add_wbuff_at ] || _relay_tun_info[ :created_at ] ) >= EXPIRE_AFTER }.keys.each do | relay_tun |
          puts "#{ Time.new } expire relay tun #{ relay_tun.object_id }"
          close_relay_tun( relay_tun )
        end
      when 'memory-info' then
        msg2 = {
          sizes: {
            relay_tcp_infos: @relay_tcp_infos.size,
            relay_tun_infos: @relay_tun_infos.size,
            tcp_infos: @tcp_infos.size,
            tun_infos: @tun_infos.size,
          }
        }

        send_msg_to_client( msg2, addrinfo )
      end
    end

    def read_relay_girl( relay_girl )
      data, addrinfo, rflags, *controls = relay_girl.recvmsg
      return if data.empty?

      # puts "debug girlc relay #{ data.inspect }"

      begin
        @girlc.sendmsg( data, 0, @girl_addr )
      rescue Exception => e
        puts "#{ Time.new } relay data to girl #{ e.class }"
      end
    end

    def read_relay_tcp( relay_tcp )
      if relay_tcp.closed? then
        puts "#{ Time.new } read relay tcp but relay tcp closed?"
        return
      end

      begin
        data = relay_tcp.read_nonblock( READ_SIZE )
      rescue Exception => e
        # puts "debug read relay tcp #{ e.class }"
        close_relay_tcp( relay_tcp )
        return
      end

      relay_tcp_info = @relay_tcp_infos[ relay_tcp ]
      relay_tcp_info[ :last_recv_at ] = Time.new
      tcp = relay_tcp_info[ :tcp ]
      add_tcp_wbuff( tcp, data )
    end

    def read_relay_tcpd( relay_tcpd )
      if relay_tcpd.closed? then
        puts "#{ Time.new } read relay tcpd but relay tcpd closed?"
        return
      end

      begin
        relay_tcp, addrinfo = relay_tcpd.accept_nonblock
      rescue Exception => e
        puts "#{ Time.new } relay tcpd accept #{ e.class }"
        return
      end

      # puts "debug accept a relay tcp"

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
        wbuff: '',            # 写前
        created_at: Time.new, # 创建时间
        last_recv_at: nil,    # 上一次收到控制流量时间
        tcp: tcp
      }

      @tcp_infos[ tcp ] = {
        wbuff: '',            # 写前
        created_at: Time.new, # 创建时间
        last_recv_at: nil,    # 上一次收到控制流量时间
        relay_tcp: relay_tcp
      }

      add_read( relay_tcp, :relay_tcp )
      add_read( tcp, :tcp )
    end

    def read_relay_tun( relay_tun )
      if relay_tun.closed? then
        puts "#{ Time.new } read relay tun but relay tun closed?"
        return
      end

      begin
        data = relay_tun.read_nonblock( READ_SIZE )
      rescue Exception => e
        # puts "debug read relay tun #{ e.class }"
        close_relay_tun( relay_tun )
        return
      end

      relay_tun_info = @relay_tun_infos[ relay_tun ]
      relay_tun_info[ :last_recv_at ] = Time.new
      tun = relay_tun_info[ :tun ]
      add_tun_wbuff( tun, data )
    end

    def read_relay_tund( relay_tund )
      if relay_tund.closed? then
        puts "#{ Time.new } read relay tund but relay tund closed?"
        return
      end

      begin
        relay_tun, addrinfo = relay_tund.accept_nonblock
      rescue Exception => e
        puts "#{ Time.new } relay tund accept #{ e.class }"
        return
      end

      # puts "debug accept a relay tun"

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
        wbuff: '',              # 写前
        created_at: Time.new,   # 创建时间
        last_add_wbuff_at: nil, # 上一次加写前的时间
        paused: false,          # 是否暂停
        tun: tun
      }

      @tun_infos[ tun ] = {
        wbuff: '',              # 写前
        created_at: Time.new,   # 创建时间
        last_add_wbuff_at: nil, # 上一次加写前的时间
        paused: false,          # 是否已暂停
        relay_tun: relay_tun
      }

      add_read( relay_tun, :relay_tun )
      add_read( tun, :tun )
    end

    def read_tcp( tcp )
      if tcp.closed? then
        puts "#{ Time.new } read tcp but tcp closed?"
        return
      end

      begin
        data = tcp.read_nonblock( READ_SIZE )
      rescue Exception => e
        # puts "debug read tcp #{ e.class }"
        close_tcp( tcp )
        return
      end

      tcp_info = @tcp_infos[ tcp ]
      tcp_info[ :last_recv_at ] = Time.new
      relay_tcp = tcp_info[ :relay_tcp ]
      add_relay_tcp_wbuff( relay_tcp, data )
    end

    def read_tun( tun )
      if tun.closed? then
        puts "#{ Time.new } read tun but tun closed?"
        return
      end

      tun_info = @tun_infos[ tun ]

      begin
        data = tun.read_nonblock( READ_SIZE )
      rescue Exception => e
        # puts "debug read tun #{ e.class }"
        close_read_tun( tun )
        return
      end

      relay_tun = tun_info[ :relay_tun ]
      add_relay_tun_wbuff( relay_tun, data )
    end

    def send_msg_to_infod( msg )
      begin
        @info.sendmsg( JSON.generate( msg ), 0, @infod_addr )
      rescue Exception => e
        puts "#{ Time.new } send msg to infod #{ e.class }"
      end
    end

    def send_msg_to_client( msg, addrinfo )
      begin
        @infod.sendmsg_nonblock( JSON.generate( msg ), 0, addrinfo )
      rescue Exception => e
        puts "#{ Time.new } send msg to client #{ e.class } #{ addrinfo.ip_unpack.inspect }"
      end
    end

    def set_tun_closing_write( tun )
      return if tun.nil? || tun.closed?
      tun_info = @tun_infos[ tun ]
      return if tun_info[ :closing_write ]
      # puts "debug set tun closing write"
      tun_info[ :closing_write ] = true
      add_write( tun )
    end

    def write_relay_tcp( relay_tcp )
      if relay_tcp.closed? then
        puts "#{ Time.new } write relay tcp but relay tcp closed?"
        return
      end

      relay_tcp_info = @relay_tcp_infos[ relay_tcp ]
      data = relay_tcp_info[ :wbuff ]

      # 写前为空，处理关闭写
      if data.empty? then
        @writes.delete( relay_tcp )
        return
      end

      # 写入
      begin
        written = relay_tcp.write_nonblock( data )
      rescue Exception => e
        # puts "debug write relay tcp #{ e.class }"
        close_relay_tcp( relay_tcp )
        return
      end

      data = data[ written..-1 ]
      relay_tcp_info[ :wbuff ] = data
    end

    def write_relay_tun( relay_tun )
      if relay_tun.closed? then
        puts "#{ Time.new } write relay tun but relay tun closed?"
        return
      end

      relay_tun_info = @relay_tun_infos[ relay_tun ]
      tun = relay_tun_info[ :tun ]
      data = relay_tun_info[ :wbuff ]

      # 写前为空，处理关闭写
      if data.empty? then
        if relay_tun_info[ :closing_write ] then
          close_write_relay_tun( relay_tun )
        else
          @writes.delete( relay_tun )
        end

        return
      end

      # 写入
      begin
        written = relay_tun.write_nonblock( data )
      rescue Exception => e
        # puts "debug write relay tun #{ e.class }"
        close_relay_tun( relay_tun )
        close_read_tun( tun )
        return
      end

      data = data[ written..-1 ]
      relay_tun_info[ :wbuff ] = data

      if tun && !tun.closed? then
        tun_info = @tun_infos[ tun ]

        if tun_info[ :paused ] && ( relay_tun_info[ :wbuff ].bytesize < RESUME_BELOW ) then
          puts "#{ Time.new } resume tun"
          add_read( tun )
          tun_info[ :paused ] = false
        end
      end
    end

    def write_tcp( tcp )
      if tcp.closed? then
        puts "#{ Time.new } write tcp but tcp closed?"
        return
      end

      tcp_info = @tcp_infos[ tcp ]
      data = tcp_info[ :wbuff ]

      # 写前为空，处理关闭写
      if data.empty? then
        @writes.delete( tcp )
        return
      end

      # puts "debug write tcp #{ data.inspect }"

      # 写入
      begin
        written = tcp.write_nonblock( data )
      rescue Exception => e
        # puts "debug write tcp #{ e.class }"
        close_tcp( tcp )
        return
      end

      data = data[ written..-1 ]
      tcp_info[ :wbuff ] = data
    end

    def write_tun( tun )
      if tun.closed? then
        puts "#{ Time.new } write tun but tun closed?"
        return
      end

      tun_info = @tun_infos[ tun ]
      relay_tun = tun_info[ :relay_tun ]
      data = tun_info[ :wbuff ]

      # 写前为空，处理关闭写
      if data.empty? then
        if tun_info[ :closing_write ] then
          close_write_tun( tun )
        else
          @writes.delete( tun )
        end

        return
      end

      # 写入
      begin
        written = tun.write_nonblock( data )
      rescue Exception => e
        # puts "debug write tun #{ e.class }"
        close_tun( tun )
        close_read_relay_tun( relay_tun )
        return
      end

      data = data[ written..-1 ]
      tun_info[ :wbuff ] = data

      if relay_tun && !relay_tun.closed? then
        relay_tun_info = @relay_tun_infos[ relay_tun ]

        if relay_tun_info[ :paused ] && ( tun_info[ :wbuff ].bytesize < RESUME_BELOW ) then
          puts "#{ Time.new } resume relay tun"
          add_read( relay_tun )
          relay_tun_info[ :paused ] = false
        end
      end
    end

  end
end
