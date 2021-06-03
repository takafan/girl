module Girl
  class ResolvdWorker

    ##
    # initialize
    #
    def initialize( resolvd_port, nameserver )
      @custom = Girl::ResolvCustom.new
      @nameserver_addr = Socket.sockaddr_in( 53, nameserver )
      @roles = {}        # :resolvd / :dst
      @reads = []
      @writes = []
      @closing_dsts = []
      @dst_infos = {}    # dst => {}
      @mutex = Mutex.new

      dotr, dotw = IO.pipe
      @dotw = dotw
      add_read( dotr, :dotr )
      new_resolvds( resolvd_port )
    end

    ##
    # looping
    #
    def looping
      puts "p#{ Process.pid } #{ Time.new } looping"
      loop_check_expire

      loop do
        rs, _ = IO.select( @reads )

        rs.each do | sock |
          case @roles[ sock ]
          when :dotr then
            read_dotr( sock )
          when :resolvd then
            read_resolvd( sock )
          when :dst then
            read_dst( sock )
          else
            puts "p#{ Process.pid } #{ Time.new } read unknown role"
            sock.close
            @reads.delete( sock )
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
    # add closing dst
    #
    def add_closing_dst( dst )
      return if dst.closed? || @closing_dsts.include?( dst )
      @closing_dsts << dst
      next_tick
    end

    ##
    # add read
    #
    def add_read( sock, role = nil )
      return if sock.closed? || @reads.include?( sock )
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
      dst.close
      @reads.delete( dst )
      @roles.delete( dst )
      @dst_infos.delete( dst )
    end

    ##
    # loop check expire
    #
    def loop_check_expire
      Thread.new do
        loop do
          sleep CHECK_EXPIRE_INTERVAL

          @mutex.synchronize do
            now = Time.new

            @dst_infos.keys.each do | dst |
              dst_info = @dst_infos[ dst ]

              if ( now - dst_info[ :created_at ] >= EXPIRE_NEW ) then
                puts "p#{ Process.pid } #{ Time.new } expire dst #{ EXPIRE_NEW }"
                add_closing_dst( dst )
              end
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
      dst.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )

      # puts "debug new a dst"
      @dst_infos[ dst ] = {
        resolvd: resolvd,
        src_addr: src_addr,
        created_at: Time.new
      }
      add_read( dst, :dst )
      send_data( dst, @nameserver_addr, data )
    end

    ##
    # new resolvds
    #
    def new_resolvds( resolvd_port )
      10.times do
        resolvd = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
        resolvd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
        resolvd.bind( Socket.sockaddr_in( resolvd_port, '0.0.0.0' ) )

        puts "p#{ Process.pid } #{ Time.new } resolvd bind on #{ resolvd_port }"
        add_read( resolvd, :resolvd )
        resolvd_port += 1
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
        puts "p#{ Process.pid } #{ Time.new } sendmsg to #{ to_addr.ip_unpack.inspect } #{ e.class }"
      end
    end

    ##
    # read dotr
    #
    def read_dotr( dotr )
      dotr.read_nonblock( READ_SIZE )

      if @closing_dsts.any? then
        @closing_dsts.each{ | dst | close_dst( dst ) }
        @closing_dsts.clear
      end
    end

    ##
    # read resolvd
    #
    def read_resolvd( resolvd )
      data, addrinfo, rflags, *controls = resolvd.recvmsg
      # puts "debug resolvd recvmsg #{ addrinfo.ip_unpack.inspect } #{ data.inspect }"
      data = @custom.decode( data )
      new_a_dst( resolvd, addrinfo.to_sockaddr, data )
    end

    ##
    # read dst
    #
    def read_dst( dst )
      begin
        data, addrinfo, rflags, *controls = dst.recvmsg
      rescue Exception => e
        puts "p#{ Process.pid } #{ Time.new } dst recvmsg #{ e.class }"
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
