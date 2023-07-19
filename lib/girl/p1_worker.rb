module Girl
  class P1Worker

    def initialize( mirrord_host, mirrord_port, infod_port, appd_host, appd_port, im )
      @mirrord_host = mirrord_host
      @mirrord_port = mirrord_port
      @appd_addr = Socket.sockaddr_in( appd_port, appd_host )
      @im = im
      @update_roles = [ :app, :p1 ] # 参与淘汰的角色
      @updates_limit = 1011         # 淘汰池上限，1015(mac) - 1 (pair) - [ ctl, info, infod ]
      @reads = []                   # 读池
      @writes = []                  # 写池
      @updates = {}                 # sock => updated_at
      @eliminate_count = 0          # 淘汰次数
      @roles = {}                   # sock => :app / :ctl / :infod / :p1
      @app_infos = {}               # app => { :p1 :wbuff :closing :paused }
      @p1_infos = {}                # p1 => { :app :wbuff :closing :paused }
      
      new_a_ctl
      new_a_infod( infod_port )
    end

    def looping
      # puts "#{ Time.new } looping"
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
            # puts "#{ Time.new } read unknown role #{ role }"
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
            # puts "#{ Time.new } write unknown role #{ role }"
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

    def add_app_wbuff( app, data )
      return if app.nil? || app.closed?
      app_info = @app_infos[ app ]
      app_info[ :wbuff ] << data
      add_write( app )
      return if app.closed?

      if app_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        p1 = app_info[ :p1 ]

        if p1 then
          p1_info = @p1_infos[ p1 ]

          if p1_info then
            # puts "#{ Time.new } pause p1"
            @reads.delete( p1 )
            p1_info[ :paused ] = true
          end
        end
      end
    end

    def add_p1_wbuff( p1, data )
      return if p1.nil? || p1.closed?
      p1_info = @p1_infos[ p1 ]
      p1_info[ :wbuff ] << data
      add_write( p1 )
      return if p1.closed?

      if p1_info[ :wbuff ].bytesize >= WBUFF_LIMIT then
        app = p1_info[ :app ]

        if app then
          app_info = @app_infos[ app ]

          if app_info then
            # puts "#{ Time.new } pause app"
            @reads.delete( app )
            app_info[ :paused ] = true
          end
        end
      end
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

    def close_app( app )
      return if app.nil? || app.closed?
      # puts "#{ Time.new } close app"
      close_sock( app )
      app_info = @app_infos.delete( app )
      set_p1_closing( app_info[ :p1 ] ) if app_info
      app_info
    end

    def close_ctl
      return if @ctl.nil? || @ctl.closed?
      close_sock( @ctl )
    end

    def close_p1( p1 )
      return if p1.nil? || p1.closed?
      # puts "#{ Time.new } close p1"
      close_sock( p1 )
      p1_info = @p1_infos.delete( p1 )
      set_app_closing( p1_info[ :app ] ) if p1_info
      p1_info
    end

    def close_sock( sock )
      return if sock.nil? || sock.closed?
      sock.close
      @reads.delete( sock )
      @writes.delete( sock )
      @updates.delete( sock )
      @roles.delete( sock )
    end

    def loop_check_expire
      Thread.new do
        loop do
          sleep CHECK_APP_EXPIRE_INTERVAL

          msg = {
            message_type: 'check-expire'
          }

          send_data( @info, JSON.generate( msg ), @infod_addr )
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

          send_data( @info, JSON.generate( msg ), @infod_addr )
        end
      end
    end

    def new_a_ctl
      ctl = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      ctl.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      ctl.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 ) if RUBY_PLATFORM.include?( 'linux' )
      mirrord_port = @mirrord_port + 10.times.to_a.sample
      mirrord_addr = Socket.sockaddr_in( mirrord_port, @mirrord_host )

      @ctl = ctl
      @ctl_info = {
        mirrord_addr: mirrord_addr
      }

      add_read( ctl, :ctl )
      # puts "#{ Time.new } send im #{ @im.inspect } #{ @mirrord_host } #{ mirrord_port }"
      send_data( ctl, @im, mirrord_addr )
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
        p1: p1,
        wbuff: '',
        closing: false,
        paused: false
      }

      @p1_infos[ p1 ] = {
        app: app,
        wbuff: [ p2_id ].pack( 'Q>' ),
        closing: false,
        paused: false
      }

      add_read( app, :app )
      add_read( p1, :p1 )
      add_write( p1 )
      # puts "#{ Time.new } new app and p1 #{ p1d_port } #{ p2_id } app infos #{ @app_infos.size } p1 infos #{ @p1_infos.size }"
    end

    def read_app( app )
      if app.closed? then
        puts "#{ Time.new } read closed app?"
        return
      end

      begin
        data = app.read_nonblock( READ_SIZE )
      rescue Exception => e
        # puts "#{ Time.new } read app #{ e.class }"
        close_app( app )
        return
      end

      set_update( app )
      app_info = @app_infos[ app ]
      p1 = app_info[ :p1 ]
      add_p1_wbuff( p1, data )
    end

    def read_ctl( ctl )
      begin
        data, addrinfo, rflags, *controls = ctl.recvmsg
      rescue Exception => e
        puts "#{ Time.new } ctl recvmsg #{ e.class }"
        return
      end

      return if data.empty?

      if addrinfo.to_sockaddr != @ctl_info[ :mirrord_addr ] then
        puts "#{ Time.new } mirrord addr not match #{ addrinfo.inspect }"
        return
      end

      p1d_port, p2_id = data.unpack( 'nQ>' )
      new_app_and_p1( p1d_port, p2_id )
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
        socks = @updates.select{ | _, updated_at | now - updated_at >= EXPIRE_APP_AFTER }.keys

        socks.each do | sock |
          case @roles[ sock ]
          when :app
            app_info = close_app( sock )
            # puts "#{ Time.new } expire app" if app_info
          when :p1
            p1_info = close_p1( sock )
            # puts "#{ Time.new } expire p1" if p1_info
          else
            close_sock( sock )
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
            updates: @updates.size,
            p1_infos: @p1_infos.size,
            app_infos: @app_infos.size
          },
          updates_limit: @updates_limit,
          eliminate_count: @eliminate_count
        }

        send_data( @infod, JSON.generate( msg2 ), addrinfo )
      end
    end

    def read_p1( p1 )
      if p1.closed? then
        puts "#{ Time.new } read closed p1?"
        return
      end

      begin
        data = p1.read_nonblock( READ_SIZE )
      rescue Exception => e
        # puts "#{ Time.new } read p1 #{ e.class }"
        close_p1( p1 )
        return
      end

      set_update( p1 )
      p1_info = @p1_infos[ p1 ]
      app = p1_info[ :app ]
      add_app_wbuff( app, data )
    end

    def send_data( sock, data, target_addr )
      begin
        sock.sendmsg( data, 0, target_addr )
      rescue Exception => e
        puts "#{ Time.new } sendmsg #{ e.class }"
      end
    end

    def set_app_closing( app )
      return if app.nil? || app.closed?
      app_info = @app_infos[ app ]
      return if app_info.nil? || app_info[ :closing ]
      app_info[ :closing ] = true
      add_write( app )
    end

    def set_p1_closing( p1 )
      return if p1.nil? || p1.closed?
      p1_info = @p1_infos[ p1 ]
      return if p1_info.nil? || p1_info[ :closing_write ]
      p1_info[ :closing ] = true
      add_write( p1 )
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
          when :app
            close_app( _sock )
          when :p1
            close_p1( _sock )
          else
            close_sock( _sock )
          end
        end

        @eliminate_count += 1
      end
    end

    def write_app( app )
      if app.closed? then
        puts "#{ Time.new } write closed app?"
        return
      end

      app_info = @app_infos[ app ]
      data = app_info[ :wbuff ]

      # 写前为空，处理关闭写
      if data.empty? then
        if app_info[ :closing ] then
          close_app( app )
        else
          @writes.delete( app )
        end

        return
      end

      # 写入
      begin
        written = app.write_nonblock( data )
      rescue Exception => e
        # puts "#{ Time.new } write app #{ e.class }"
        close_app( app )
        return
      end

      set_update( app )
      data = data[ written..-1 ]
      app_info[ :wbuff ] = data
      p1 = app_info[ :p1 ]

      if p1 && !p1.closed? then
        p1_info = @p1_infos[ p1 ]

        if p1_info[ :paused ] && ( app_info[ :wbuff ].bytesize < RESUME_BELOW ) then
          # puts "#{ Time.new } resume p1"
          add_read( p1 )
          p1_info[ :paused ] = false unless p1.closed?
        end
      end
    end

    def write_p1( p1 )
      if p1.closed? then
        puts "#{ Time.new } write closed p1?"
        return
      end

      p1_info = @p1_infos[ p1 ]
      app = p1_info[ :app ]
      data = p1_info[ :wbuff ]

      # 写前为空，处理关闭写
      if data.empty? then
        if p1_info[ :closing ] then
          close_p1( p1 )
        else
          @writes.delete( p1 )
        end

        return
      end

      # 写入
      begin
        written = p1.write_nonblock( data )
      rescue Exception => e
        # puts "#{ Time.new } write p1 #{ e.class }"
        close_p1( p1 )
        return
      end

      set_update( p1 )
      data = data[ written..-1 ]
      p1_info[ :wbuff ] = data

      if app && !app.closed? then
        app_info = @app_infos[ app ]

        if app_info[ :paused ] && ( p1_info[ :wbuff ].bytesize < RESUME_BELOW ) then
          # puts "#{ Time.new } resume app"
          add_read( app )
          app_info[ :paused ] = false unless app.closed?
        end
      end
    end

  end
end
