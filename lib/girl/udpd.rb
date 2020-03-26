require 'girl/version'
require 'socket'

##
# Girl::Udpd - 转发udp。远端。
#
module Girl
  class Udpd

    def initialize( port = 3030 )
      ctlr, ctlw = IO.pipe

      udpd = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      udpd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      udpd.bind( Socket.sockaddr_in( port, '0.0.0.0' ) )
      puts "udpd bound on #{ port } #{ Time.new }"

      @mutex = Mutex.new
      @ctlw = ctlw
      @udpd = udpd
      @reads = [ ctlr, udpd ]
      @writes = []
      @closings = []
      @roles = {
        ctlr => :ctlr, # :ctlr / :udpd / :dest
        udpd => :udpd
      }
      @dests = {}      # us_addr => dest
      @dest_infos = {} # dest => {}
                       #   us_addr: [ udp_addr, src_addr ].join
                       #   udp_addr: udp_addr
                       #   src_addr: src_addr
                       #   last_traff_at: now
      @halfs = {}      # udp_addr => [ src_addr, dest_addr ].join
    end

    def looping
      loop_expire

      loop do
        rs, ws = IO.select( @reads, @writes )

        @mutex.synchronize do
          rs.each do | sock |
            case @roles[ sock ]
            when :ctlr
              read_ctlr( sock )
            when :udpd
              read_udpd( sock )
            when :dest
              read_dest( sock )
            end
          end

          ws.each do | sock |
            write_dest( sock )
          end
        end
      end
    end

    def quit!
      exit
    end

    private

    def read_ctlr( ctlr )
      us_addr = ctlr.read( 32 )
      dest = @dests[ us_addr ]

      if dest
        # puts "debug expire dest #{ us_addr.inspect } #{ Time.new }"
        add_closing( dest )
      end
    end

    def read_udpd( udpd )
      data, addrinfo, rflags, *controls = udpd.recvmsg
      return if data.size < 32

      udp_addr = addrinfo.to_sockaddr

      if @halfs[ udp_addr ].nil? && data.size == 32
         @halfs[ udp_addr ] = data
         return
      end

      if @halfs[ udp_addr ]
        src_addr = @halfs[ udp_addr ][ 0, 16 ]
        dest_addr = @halfs[ udp_addr ][ 16, 16 ]
        data = "#{ dest_addr }#{ data }"
        @halfs.delete( udp_addr )
      else
        src_addr = data[ 0, 16 ]
        dest_addr = data[ 16, 16 ]
        data = data[ 16..-1 ]
      end

      return unless Addrinfo.new( src_addr ).ipv4?
      return unless Addrinfo.new( dest_addr ).ipv4?

      us_addr = [ udp_addr, src_addr ].join
      dest = @dests[ us_addr ]

      unless dest
        dest = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
        dest.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
        dest.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )

        @dests[ us_addr ] = dest
        @dest_infos[ dest ] = {
          us_addr: us_addr,
          udp_addr: udp_addr,
          src_addr: src_addr,
          wbuffs: [],
          last_traff_at: Time.new
        }

        @roles[ dest ] = :dest
        @reads << dest
      end

      dest_info = @dest_infos[ dest ]
      dest_info[ :wbuffs ] << data
      add_write( dest )
    end

    def read_dest( dest )
      data, addrinfo, rflags, *controls = dest.recvmsg

      dest_info = @dest_infos[ dest ]
      return unless dest_info

      dest_info[ :last_traff_at ] = Time.new
      dest_addr = addrinfo.to_sockaddr
      sendmsg_to_udp( "#{ dest_addr }#{ dest_info[ :src_addr ] }#{ data }", dest_info[ :udp_addr ] )
    end

    def write_dest( dest )
      if @closings.include?( dest )
        close_dest( dest )
        return
      end

      dest_info = @dest_infos[ dest ]
      data = dest_info[ :wbuffs ].shift

      unless data
        @writes.delete( dest )
        return
      end

      dest_addr = data[ 0, 16 ]
      data = data[ 16..-1 ]

      begin
        dest.sendmsg( data, 0, dest_addr )
      rescue Errno::EACCES, Errno::EINTR => e
        puts "dest sendmsg #{ e.class } #{ Time.new }"
        add_closing( dest )
        return
      end

      dest_info[ :last_traff_at ] = Time.new
    end

    def add_write( dest )
      unless @writes.include?( dest )
        @writes << dest
      end
    end

    def add_closing( dest )
      unless @closings.include?( dest )
        @closings << dest
      end

      add_write( dest )
    end

    def close_dest( dest )
      dest.close
      @reads.delete( dest )
      @writes.delete( dest )
      @closings.delete( dest )
      @roles.delete( dest )
      dest_info = @dest_infos.delete( dest )
      @dests.delete( dest_info[ :us_addr ] )
    end

    def sendmsg_to_udp( data, udp_addr )
      begin
        @udpd.sendmsg( data, 0, udp_addr )
      rescue Errno::EMSGSIZE => e
        puts "#{ e.class } #{ Time.new }"
        [ data[ 0, 32 ], data[ 32..-1 ] ].each do | part |
          @udpd.sendmsg( part, 0, udp_addr )
        end
      end
    end

    def loop_expire
      Thread.new do
        loop do
          sleep 60

          @mutex.synchronize do
            now = Time.new

            @dest_infos.values.each do | dest_info |
              if now - dest_info[ :last_traff_at ] > 1800
                @ctlw.write( dest_info[ :us_addr ] )
              end
            end
          end
        end
      end
    end

  end
end
