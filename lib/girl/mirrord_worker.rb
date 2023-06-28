module Girl
  class MirrordWorker

    def initialize( mirrord_port, p2d_host, im_infos )
      @updates_limit = 1023 - 11 - im_infos.size * 2 # 应对 FD_SETSIZE (1024)，参与淘汰的更新池上限，1023 - [ infod, mirrord * 10, p1d * im_infos.size, p2d * im_infos.size ]
      @eliminate_size = @updates_limit - 255         # 淘汰数，保留255个最近的，其余淘汰
      @update_roles = [ :p1, :p2 ]                   # 参与淘汰的角色
      @reads = []
      @writes = []

      @updates = {}    # sock => updated_at
      @roles = {}      # :infod / :mirrord / :p1 / :p1d / :p2 / :p2d
      @room_infos = {} # im => { :mirrord :p1_addrinfo :updated_at :p1d :p2d :p2d_port :p1d_port }
      @p1d_infos = {}  # p1d => { :im }
      @p2d_infos = {}  # p2d => { :im }
      @p1_infos = {}   # p1 => { :addrinfo :im :p2 :wbuff :closing :paused }
      @p2_infos = {}   # p2 => { :addrinfo :im :p1 :rbuff :wbuff :closing :paused }
      @p2d_host = p2d_host

      new_mirrords( mirrord_port )
      new_a_infod( mirrord_port )
      set_im_infos( im_infos )
    end

    def looping
      puts "#{ Time.new } looping"
      loop_check_expire

      loop do
        rs, ws = IO.select( @reads, @writes )

        rs.each do | sock |
          role = @roles[ sock ]

          case role
          when :infod
            read_infod( sock )
          when :mirrord
            read_mirrord( sock )
          when :p1
            read_p1( sock )
          when :p1d
            read_p1d( sock )
          when :p2
            read_p2( sock )
          when :p2d
            read_p2d( sock )
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

    def quit!
      # puts "debug exit"
      exit
    end

    private

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

    def add_p2_rbuff( p2, data )
      return if p2.nil? || p2.closed?
      p2_info = @p2_infos[ p2 ]
      p2_info[ :rbuff ] << data

      if p2_info[ :rbuff ].bytesize >= WBUFF_LIMIT then
        # puts "debug p2.rbuff full"
        close_p2( p2 )
      end
    end

    def add_p2_wbuff( p2, data )
      return if p2.nil? || p2.closed?
      p2_info = @p2_infos[ p2 ]
      p2_info[ :wbuff ] << data
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

    def close_p1( p1 )
      return if p1.nil? || p1.closed?
      # puts "debug close p1"
      close_sock( p1 )
      p1_info = @p1_infos.delete( p1 )
      set_p2_closing( p1_info[ :p2 ] ) if p1_info
      p1_info
    end

    def close_p2( p2 )
      return if p2.nil? || p2.closed?
      # puts "debug close p2"
      close_sock( p2 )
      p2_info = @p2_infos.delete( p2 )
      set_p1_closing( p2_info[ :p1 ] ) if p2_info
      p2_info
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

          send_msg_to_infod( msg )
        end
      end
    end

    def new_a_infod( mirrord_port )
      infod_port = mirrord_port + 10
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

    def new_mirrords( begin_port )
      10.times do | i |
        mirrord_port = begin_port + i
        mirrord = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )

        if RUBY_PLATFORM.include?( 'linux' ) then
          mirrord.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
        end
        
        mirrord.bind( Socket.sockaddr_in( mirrord_port, '0.0.0.0' ) )
        puts "#{ Time.new } mirrord bind on #{ mirrord_port }"
        add_read( mirrord, :mirrord )
      end
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
        socks = @updates.select{ | _, updated_at | now - updated_at >= EXPIRE_APP_AFTER }.keys

        socks.each do | sock |
          case @roles[ sock ]
          when :p1
            p1_info = close_p1( sock )
            puts "#{ Time.new } expire p1 #{ p1_info[ :im ] } #{ p1_info[ :addrinfo ].inspect }" if p1_info
          when :p2
            p2_info = close_p2( sock )
            puts "#{ Time.new } expire p2 #{ p2_info[ :im ] } #{ p2_info[ :addrinfo ].inspect }" if p2_info
          else
            close_sock( sock )
          end
        end
      when 'memory-info' then
        data2 = @room_infos.sort_by{ | _, _info | _info[ :p2d_port ] }.map do | im, info |
          [
            info[ :updated_at ],
            info[ :p2d_port ],
            info[ :p1d_port ],
            im + ' ' * ( ROOM_TITLE_LIMIT - im.size ),
            info[ :p1_addrinfo ].ip_unpack.join( ':' )
          ].join( ' ' )
        end.join( "\n" )
  
        send_data( infod, data2, addrinfo )
      end
    end

    def read_mirrord( mirrord )
      data, addrinfo, rflags, *controls = mirrord.recvmsg
      return if data.empty? || ( data.size > ROOM_TITLE_LIMIT ) || data =~ /\r|\n/

      im = data
      room_info = @room_infos[ im ]

      if room_info then
        room_info[ :mirrord ] = mirrord
        room_info[ :p1_addrinfo ] = addrinfo
        room_info[ :updated_at ] = Time.new
      elsif @im_infos.include?( im ) then
        im_info = @im_infos[ im ]
        p2d_port, p1d_port = im_info[ :p2d_port ], im_info[ :p1d_port ]
        p1d = new_a_listener( p1d_port, '0.0.0.0' )
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
          p2d: p2d,
          p1d_port: p1d.local_address.ip_port,
          p2d_port: p2d.local_address.ip_port
        }

        add_read( p1d, :p1d )
        add_read( p2d, :p2d )
      else
        puts "#{ Time.new } unknown room #{ im.inspect }"
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
        # puts "debug read p1 #{ e.class }"
        close_p1( p1 )
        return
      end

      set_update( p1 )
      p1_info = @p1_infos[ p1 ]
      p2 = p1_info[ :p2 ]

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

    def read_p1d( p1d )
      if p1d.closed? then
        puts "#{ Time.new } read closed p1d?"
        return
      end

      p1d_info = @p1d_infos[ p1d ]
      im = p1d_info[ :im ]

      begin
        p1, addrinfo = p1d.accept_nonblock
      rescue Exception => e
        puts "#{ Time.new } p1d accept #{ e.class } #{ im.inspect }"
        return
      end

      @p1_infos[ p1 ] = {
        addrinfo: addrinfo, # 地址
        im: im,             # 标识
        p2: nil,            # 对应p2
        wbuff: '',          # 写前
        closing: false,     # 是否准备关闭
        paused: false       # 是否已暂停
      }

      add_read( p1, :p1 )
      puts "#{ Time.new } here comes a p1 #{ im.inspect } #{ addrinfo.inspect }"
    end

    def read_p2( p2 )
      if p2.closed? then
        puts "#{ Time.new } read closed p2?"
        return
      end

      begin
        data = p2.read_nonblock( READ_SIZE )
      rescue Exception => e
        # puts "debug read p2 #{ e.class }"
        close_p2( p2 )
        return
      end

      set_update( p2 )
      p2_info = @p2_infos[ p2 ]
      p1 = p2_info[ :p1 ]

      if p1 then
        add_p1_wbuff( p1, data )
      else
        add_p2_rbuff( p2, data )
      end
    end

    def read_p2d( p2d )
      if p2d.closed? then
        puts "#{ Time.new } read closed p2d?"
        return
      end

      p2d_info = @p2d_infos[ p2d ]
      im = p2d_info[ :im ]

      begin
        p2, addrinfo = p2d.accept_nonblock
      rescue Exception => e
        puts "#{ Time.new } p2d accept #{ e.class } #{ im.inspect }"
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
        closing: false,       # 是否准备关闭
        paused: false         # 是否已暂停
      }

      add_read( p2, :p2 )

      puts "#{ Time.new } here comes a p2 #{ im.inspect } #{ addrinfo.inspect } #{ p2_id }"
      puts "rooms #{ @room_infos.size } p1ds #{ @p1d_infos.size } p2ds #{ @p2d_infos.size } p1s #{ @p1_infos.size } p2s #{ @p2_infos.size } updates #{ @updates.size }"
      data = [ p1d_port, p2_id ].pack( 'nQ>' )
      send_data( room_info[ :mirrord ], data, room_info[ :p1_addrinfo ] )
    end

    def send_data( sock, data, target_addr )
      begin
        sock.sendmsg_nonblock( data, 0, target_addr )
      rescue Exception => e
        puts "#{ Time.new } sendmsg #{ e.class }"
      end
    end

    def send_msg_to_infod( msg )
      begin
        @info.sendmsg( JSON.generate( msg ), 0, @infod_addr )
      rescue Exception => e
        puts "#{ Time.new } send msg to infod #{ e.class }"
      end
    end

    def set_im_infos( im_infos )
      @im_infos = {}

      im_infos.each do | info |
        im, p2d_port, p1d_port = info[ :im ], info[ :p2d_port ], info[ :p1d_port ]
        
        @im_infos[ im ] = {
          p2d_port: p2d_port,
          p1d_port: p1d_port
        }
      end
    end

    def set_p1_closing( p1 )
      return if p1.nil? || p1.closed?
      p1_info = @p1_infos[ p1 ]
      return if p1_info.nil? || p1_info[ :closing ]
      p1_info[ :closing ] = true
      add_write( p1 )
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

      if @updates.size >= @updates_limit then
        puts "#{ Time.new } eliminate updates"

        @updates.sort_by{ | _, updated_at | updated_at }.map{ | _sock, _ | _sock }[ 0, @eliminate_size ].each do | _sock |
          case @roles[ _sock ]
          when :p1
            close_p1( _sock )
          when :p2
            close_p2( _sock )
          else
            close_sock( _sock )
          end
        end
      end
    end

    def write_p1( p1 )
      if p1.closed? then
        puts "#{ Time.new } write closed p1?"
        return
      end

      p1_info = @p1_infos[ p1 ]
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
        # puts "debug write p1 #{ e.class }"
        close_p1( p1 )
        return
      end

      set_update( p1 )
      data = data[ written..-1 ]
      p1_info[ :wbuff ] = data
      p2 = p1_info[ :p2 ]

      if p2 && !p2.closed? then
        p2_info = @p2_infos[ p2 ]

        if p2_info[ :paused ] && ( p1_info[ :wbuff ].bytesize < RESUME_BELOW ) then
          puts "#{ Time.new } resume p2 #{ p2_info[ :im ].inspect } #{ p2_info[ :addrinfo ].inspect }"
          add_read( p2 )
          p2_info[ :paused ] = false
        end
      end
    end

    def write_p2( p2 )
      if p2.closed? then
        puts "#{ Time.new } write closed p2?"
        return
      end

      p2_info = @p2_infos[ p2 ]
      data = p2_info[ :wbuff ]

      # 写前为空，处理关闭写
      if data.empty? then
        if p2_info[ :closing ] then
          close_p2( p2 )
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
        close_p2( p2 )
        return
      end

      set_update( p2 )
      data = data[ written..-1 ]
      p2_info[ :wbuff ] = data
      p1 = p2_info[ :p1 ]

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
