module Girl
  class P1Worker

    def initialize( mirrord_host, mirrord_port, infod_port, appd_host, appd_port, im )
      @reads = []
      @writes = []
      @roles = {}     # sock => :app / :ctl / :infod / :p1
      @p1_infos = {}  # p1 => { :wbuff, :closing_write, :paused, :app }
      @app_infos = {} # app => { :wbuff, :created_at, :last_recv_at, :last_sent_at, :closing_write, :paused, :p1 }
      @mirrord_host = mirrord_host
      @mirrord_port = mirrord_port
      @appd_addr = Socket.sockaddr_in( appd_port, appd_host )
      @im = im

      new_a_ctl
      new_a_infod( infod_port )
    end

    def looping
      puts "#{ Time.new } looping"
      loop_renew_ctl
      loop_check_expire

      loop do
        rs, ws = IO.select( @reads, @writes )

        rs.each do | sock |
          role = @roles[ sock ]

          case role
          when :app then
            read_app( sock )
          when :ctl then
            read_ctl( sock )
          when :infod
            read_infod( sock )
          when :p1 then
            read_p1( sock )
          else
            puts "#{ Time.new } read unknown role #{ role }"
            close_sock( sock )
          end
        end

        ws.each do | sock |
          role = @roles[ sock ]

          case role
          when :app then
            write_app( sock )
          when :p1 then
            write_p1( sock )
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

    def add_app_wbuff( app, data )
      return if app.nil? || app.closed?
      app_info = @app_infos[ app ]
      app_info[ :wbuff ] << data
      app_info[ :last_recv_at ] = Time.new
      add_write( app )

      if app_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        p1 = app_info[ :p1 ]

        unless p1.closed? then
          puts "#{ Time.new } pause p1"
          @reads.delete( p1 )
          p1_info = @p1_infos[ p1 ]
          p1_info[ :paused ] = true
        end
      end
    end

    def add_p1_wbuff( p1, data )
      return if p1.nil? || p1.closed?
      p1_info = @p1_infos[ p1 ]
      p1_info[ :wbuff ] << data
      add_write( p1 )

      if p1_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        app = p1_info[ :app ]

        unless app.closed? then
          puts "#{ Time.new } pause app"
          @reads.delete( app )
          app_info = @app_infos[ app ]
          app_info[ :paused ] = true
        end
      end
    end

    def add_read( sock, role = nil )
      return if sock.nil? || sock.closed? || @reads.include?( sock )
      @reads << sock

      if role then
        @roles[ sock ] = role
      end
    end

    def add_write( sock )
      return if sock.nil? || sock.closed? || @writes.include?( sock )
      @writes << sock
    end

    def close_app( app )
      return if app.nil? || app.closed?
      puts "#{ Time.new } close app"
      close_sock( app )
      app_info = @app_infos.delete( app )

      if app_info then
        close_p1( app_info[ :p1 ] )
      end
    end

    def close_ctl
      return if @ctl.nil? || @ctl.closed?
      close_sock( @ctl )
    end

    def close_p1( p1 )
      return if p1.nil? || p1.closed?
      puts "#{ Time.new } close p1"
      close_sock( p1 )
      @p1_infos.delete( p1 )
    end

    def close_read_app( app )
      return if app.nil? || app.closed?
      # puts "debug close read app"
      app.close_read
      @reads.delete( app )

      if app.closed? then
        # puts "debug app closed"
        @writes.delete( app )
        @roles.delete( app )
        @app_infos.delete( app )
      end
    end

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

    def close_sock( sock )
      return if sock.nil? || sock.closed?
      sock.close
      @reads.delete( sock )
      @writes.delete( sock )
      @roles.delete( sock )
    end

    def close_write_app( app )
      return if app.nil? || app.closed?
      # puts "debug close write app"
      app.close_write
      @writes.delete( app )

      if app.closed? then
        # puts "debug app closed"
        @reads.delete( app )
        @roles.delete( app )
        @app_infos.delete( app )
      end
    end

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

    def loop_renew_ctl
      Thread.new do
        loop do
          sleep RENEW_CTL_INTERVAL

          msg = {
            message_type: 'renew-ctl'
          }

          send_msg_to_infod( msg )
        end
      end
    end

    def new_a_ctl
      ctl = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      ctl.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )

      if RUBY_PLATFORM.include?( 'linux' ) then
        ctl.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      end

      mirrord_port = @mirrord_port + 10.times.to_a.sample
      mirrord_addr = Socket.sockaddr_in( mirrord_port, @mirrord_host )

      @ctl = ctl
      @ctl_info = {
        mirrord_addr: mirrord_addr
      }

      add_read( ctl, :ctl )
      puts "#{ Time.new } send im #{ @im.inspect } #{ @mirrord_host } #{ mirrord_port }"
      send_im
    end

    def new_a_infod( infod_port )
      infod_addr = Socket.sockaddr_in( infod_port, '127.0.0.1' )
      infod = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )

      if RUBY_PLATFORM.include?( 'linux' ) then
        infod.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      end

      infod.bind( infod_addr )
      puts "#{ Time.new } infod bind on #{ infod_port }"
      add_read( infod, :infod )
      info = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      @infod_addr = infod_addr
      @infod = infod
      @info = info
    end

    def new_app_and_p1( p1d_port, p2_id )
      app = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      app.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )

      begin
        app.connect_nonblock( @appd_addr )
      rescue IO::WaitWritable
      rescue Exception => e
        puts "#{ Time.new } app connect appd addr #{ e.class }"
        app.close
        return
      end

      p1 = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      p1.setsockopt( Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1 )

      begin
        p1.connect_nonblock( Socket.sockaddr_in( p1d_port, @mirrord_host ) )
      rescue IO::WaitWritable
      rescue Exception => e
        puts "#{ Time.new } connect p1d #{ e.class }"
        app.close
        p1.close
        return
      end

      @app_infos[ app ] = {
        wbuff: '',
        created_at: Time.new,
        last_recv_at: nil,
        last_sent_at: nil,
        closing_write: false,
        paused: false,
        p1: p1
      }

      @p1_infos[ p1 ] = {
        wbuff: [ p2_id ].pack( 'Q>' ),
        closing_write: false,
        paused: false,
        app: app
      }

      add_read( app, :app )
      add_read( p1, :p1 )
      add_write( p1 )
      puts "#{ Time.new } new app and p1 #{ p1d_port } #{ p2_id } app infos #{ @app_infos.size } p1 infos #{ @p1_infos.size }"
    end

    def read_app( app )
      if app.closed? then
        puts "#{ Time.new } read app but app closed?"
        return
      end

      app_info = @app_infos[ app ]
      p1 = app_info[ :p1 ]

      begin
        data = app.read_nonblock( READ_SIZE )
      rescue Exception => e
        puts "#{ Time.new } read app #{ e.class }"
        close_read_app( app )
        set_p1_closing_write( p1 )
        return
      end

      add_p1_wbuff( p1, data )
    end

    def read_ctl( ctl )
      if ctl.closed? then
        puts "#{ Time.new } read ctl but ctl closed?"
        return
      end

      data, addrinfo, rflags, *controls = ctl.recvmsg
      return if data.empty?

      if addrinfo.to_sockaddr != @ctl_info[ :mirrord_addr ] then
        puts "#{ Time.new } mirrord addr not match #{ addrinfo.inspect }"
        return
      end

      p1d_port, p2_id = data.unpack( 'nQ>' )
      new_app_and_p1( p1d_port, p2_id )
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

        @app_infos.each do | app, app_info |
          last_recv_at = app_info[ :last_recv_at ] || app_info[ :created_at ]
          last_sent_at = app_info[ :last_sent_at ] || app_info[ :created_at ]

          if ( now - last_recv_at >= EXPIRE_AFTER ) && ( now - last_sent_at >= EXPIRE_AFTER ) then
            puts "#{ Time.new } expire app"
            close_app( app )
          end
        end
      when 'renew-ctl' then
        if @ctl && !@ctl.closed? then
          close_ctl
          new_a_ctl
        end
      when 'memory-info' then
        msg2 = {
          sizes: {
            p1_infos: @p1_infos.size,
            app_infos: @app_infos.size
          }
        }

        begin
          @infod.sendmsg_nonblock( JSON.generate( msg2 ), 0, addrinfo )
        rescue Exception => e
          puts "#{ Time.new } send memory info #{ e.class } #{ addrinfo.ip_unpack.inspect }"
        end
      end
    end

    def read_p1( p1 )
      if p1.closed? then
        puts "#{ Time.new } read p1 but p1 closed?"
        return
      end

      p1_info = @p1_infos[ p1 ]
      app = p1_info[ :app ]

      begin
        data = p1.read_nonblock( READ_SIZE )
      rescue Exception => e
        puts "#{ Time.new } read p1 #{ e.class }"
        close_read_p1( p1 )
        set_app_closing_write( app )
        return
      end

      add_app_wbuff( app, data )
    end

    def send_im
      begin
        @ctl.sendmsg( @im, 0, @ctl_info[ :mirrord_addr ] )
      rescue Exception => e
        puts "#{ Time.new } ctl sendmsg #{ e.class }"
      end
    end

    def send_msg_to_infod( msg )
      begin
        @info.sendmsg( JSON.generate( msg ), 0, @infod_addr )
      rescue Exception => e
        puts "#{ Time.new } send msg to infod #{ e.class }"
      end
    end

    def set_app_closing_write( app )
      return if app.nil? || app.closed?
      app_info = @app_infos[ app ]
      return if app_info[ :closing_write ]
      app_info[ :closing_write ] = true
      add_write( app )
    end

    def set_p1_closing_write( p1 )
      return if p1.nil? || p1.closed?
      p1_info = @p1_infos[ p1 ]
      return if p1_info[ :closing_write ]
      # puts "debug set p1 closing write"
      p1_info[ :closing_write ] = true
      add_write( p1 )
    end

    def write_app( app )
      if app.closed? then
        puts "#{ Time.new } write app but app closed?"
        return
      end

      app_info = @app_infos[ app ]
      p1 = app_info[ :p1 ]
      data = app_info[ :wbuff ]

      # 写前为空，处理关闭写
      if data.empty? then
        if app_info[ :closing_write ] then
          close_write_app( app )
        else
          @writes.delete( app )
        end

        return
      end

      # 写入
      begin
        written = app.write_nonblock( data )
      rescue Exception => e
        puts "#{ Time.new } write app #{ e.class }"
        close_write_app( app )
        close_read_p1( p1 )
        return
      end

      data = data[ written..-1 ]
      app_info[ :wbuff ] = data

      if p1 && !p1.closed? then
        p1_info = @p1_infos[ p1 ]

        if p1_info[ :paused ] && ( app_info[ :wbuff ].bytesize < RESUME_BELOW ) then
          puts "#{ Time.new } resume p1"
          add_read( p1 )
          p1_info[ :paused ] = false
        end
      end
    end

    def write_p1( p1 )
      if p1.closed? then
        puts "#{ Time.new } write p1 but p1 closed?"
        return
      end

      p1_info = @p1_infos[ p1 ]
      app = p1_info[ :app ]
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
        puts "#{ Time.new } write p1 #{ e.class }"
        close_write_p1( p1 )
        close_read_app( app )
        return
      end

      data = data[ written..-1 ]
      p1_info[ :wbuff ] = data

      if app && !app.closed? then
        app_info = @app_infos[ app ]

        if app_info[ :paused ] && ( p1_info[ :wbuff ].bytesize < RESUME_BELOW ) then
          puts "#{ Time.new } resume app"
          add_read( app )
          app_info[ :paused ] = false
        end

        app_info[ :last_sent_at ] = Time.new
      end
    end

  end
end
