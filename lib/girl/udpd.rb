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
      @roles = {
        ctlr => :ctlr, # :ctlr / :udpd / :dest
        udpd => :udpd
      }
      @dests = {}      # usd_addr => dest
      @dest_infos = {} # dest => {}
                       #   usd_addr: [ udp_addr, src_addr, dest_addr ].join
                       #   udp_addr: udp_addr
                       #   src_addr: src_addr
                       #   last_traff_at: now
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
            close_dest( sock )
          end
        end
      end
    end

    def quit!
      exit
    end

    private

    def read_ctlr( ctlr )
      usd_addr = ctlr.read( 48 )
      dest = @dests[ usd_addr ]

      if dest
        unless @writes.include?( dest )
          # puts "debug expire dest #{ usd_addr.inspect } #{ Time.new }"
          @writes << dest
        end
      end
    end

    def read_udpd( udpd )
      data, addrinfo, rflags, *controls = udpd.recvmsg
      return if data.size < 33

      udp_addr = addrinfo.to_sockaddr

      src_addr = data[ 0, 16 ]
      return unless Addrinfo.new( src_addr ).ipv4?

      dest_addr = data[ 16, 16 ]
      return unless Addrinfo.new( dest_addr ).ipv4?

      usd_addr = [ udp_addr, src_addr, dest_addr ].join
      data = data[ 32..-1 ]
      dest = @dests[ usd_addr ]

      unless dest
        dest = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
        dest.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
        dest.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )
        # puts "debug a new dest bound on #{ dest.local_address.ip_unpack.last } #{ Time.new }"

        @dests[ usd_addr ] = dest
        @dest_infos[ dest ] = {
          usd_addr: usd_addr,
          udp_addr: udp_addr,
          src_addr: src_addr,
          last_traff_at: Time.new
        }

        @roles[ dest ] = :dest
        @reads << dest
      end

      begin
        dest.sendmsg( data, 0, dest_addr )
      rescue Errno::EACCES, Errno::EINTR => e
        puts "dest sendmsg #{ e.class } #{ Time.new }"
        @ctlw.write( usd_addr )
      end
    end

    def read_dest( dest )
      data, addrinfo, rflags, *controls = dest.recvmsg

      dest_info = @dest_infos[ dest ]
      return unless dest_info

      dest_info[ :last_traff_at ] = Time.new
      @udpd.sendmsg( "#{ dest_info[ :src_addr ] }#{ data }", 0, dest_info[ :udp_addr ] )
    end

    def close_dest( dest )
      dest.close
      @reads.delete( dest )
      @writes.delete( dest )
      @roles.delete( dest )
      dest_info = @dest_infos.delete( dest )
      @dests.delete( dest_info[ :usd_addr ] )
    end

    def loop_expire
      Thread.new do
        loop do
          sleep 60

          @mutex.synchronize do
            now = Time.new

            @dest_infos.values.each do | dest_info |
              if now - dest_info[ :last_traff_at ] > 1800
                @ctlw.write( dest_info[ :usd_addr ] )
              end
            end
          end
        end
      end
    end

  end
end
