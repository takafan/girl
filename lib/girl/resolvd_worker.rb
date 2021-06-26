module Girl
  class ResolvdWorker

    ##
    # initialize
    #
    def initialize( resolvd_port, nameserver )
      @custom = Girl::ResolvCustom.new
      @nameserver_addr = Socket.sockaddr_in( 53, nameserver )
      @roles = {}        # :dotr / :resolvd / :dst
      @reads = []
      @dst_infos = {}    # dst => { :resolvd, :src_addr, :created_at, :closing }
      @mutex = Mutex.new

      new_a_pipe
      new_resolvds( resolvd_port )
    end

    ##
    # looping
    #
    def looping
      puts "#{ Time.new } looping"
      loop_check_state

      loop do
        rs, _ = IO.select( @reads )

        rs.each do | sock |
          role = @roles[ sock ]

          case role
          when :dotr then
            read_dotr( sock )
          when :resolvd then
            read_resolvd( sock )
          when :dst then
            read_dst( sock )
          else
            puts "#{ Time.new } read unknown role #{ role }"
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
    # add read
    #
    def add_read( sock, role = nil )
      return if sock.nil? || sock.closed? || @reads.include?( sock )
      @reads << sock

      if role then
        @roles[ sock ] = role
      end

      next_tick
    end

    ##
    # close dst
    #
    def close_dst( dst )
      # puts "debug close dst"
      close_sock( dst )
      @dst_infos.delete( dst )
    end

    ##
    # close sock
    #
    def close_sock( sock )
      return if sock.nil? || sock.closed?
      sock.close
      @reads.delete( sock )
      @roles.delete( sock )
    end

    ##
    # loop check state
    #
    def loop_check_state
      Thread.new do
        loop do
          sleep CHECK_STATE_INTERVAL

          @mutex.synchronize do
            now = Time.new

            @dst_infos.select{ | dst, info | !dst.closed? && ( now - info[ :created_at ] >= EXPIRE_NEW ) }.values.each do | dst_info |
              puts "#{ Time.new } expire dst"
              dst_info[ :closing ] = true
              next_tick
            end
          end
        end
      end
    end

    ##
    # new a dst
    #
    def new_a_dst( resolvd, src_addr, data )
      dst = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      dst.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )

      # puts "debug new a dst"
      @dst_infos[ dst ] = {
        resolvd: resolvd,
        src_addr: src_addr,
        created_at: Time.new,
        closing: false
      }

      add_read( dst, :dst )
      send_data( dst, @nameserver_addr, data )
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
    # new resolvds
    #
    def new_resolvds( begin_port )
      10.times do | i |
        resolvd_port = begin_port + i
        resolvd = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
        resolvd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
        resolvd.bind( Socket.sockaddr_in( resolvd_port, '0.0.0.0' ) )

        puts "#{ Time.new } resolvd bind on #{ resolvd_port }"
        add_read( resolvd, :resolvd )
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
    def send_data( sock, to_addr, data )
      begin
        sock.sendmsg_nonblock( data, 0, to_addr )
      rescue Exception => e
        puts "#{ Time.new } sendmsg #{ e.class } #{ to_addr.inspect }"
      end
    end

    ##
    # read dotr
    #
    def read_dotr( dotr )
      dotr.read_nonblock( READ_SIZE )
      @dst_infos.select{ | _, info | info[ :closing ] }.keys.each{ | dst | close_dst( dst ) }
    end

    ##
    # read resolvd
    #
    def read_resolvd( resolvd )
      data, addrinfo, rflags, *controls = resolvd.recvmsg
      # puts "debug resolvd recvmsg #{ addrinfo.ip_unpack.inspect } #{ data.inspect }"
      data = @custom.decode( data )
      new_a_dst( resolvd, addrinfo, data )
    end

    ##
    # read dst
    #
    def read_dst( dst )
      if dst.closed? then
        puts "#{ Time.new } read dst but dst closed?"
        return
      end

      begin
        data, addrinfo, rflags, *controls = dst.recvmsg
      rescue Exception => e
        puts "#{ Time.new } dst recvmsg #{ e.class }"
        close_dst( dst )
        return
      end

      # puts "debug dst recvmsg #{ addrinfo.ip_unpack.inspect } #{ data.inspect }"
      dst_info = @dst_infos[ dst ]
      data = @custom.encode( data )
      send_data( dst_info[ :resolvd ], dst_info[ :src_addr ], data )
      close_dst( dst )
    end

  end
end
