require 'girl/hex'
require 'girl/version'
require 'socket'

##
# Girl::Udpd - 转发udp。远端。
#
module Girl
  class Udpd

    def initialize( port = 3030 )
      @hex = Girl::Hex.new
      @mutex = Mutex.new
      @reads = []
      @writes = []
      @roles = {} # sock => :ctlr / :udpd / :dest
      @infos = {} # udpd => {}

      udpd = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      udpd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      udpd.bind( Socket.sockaddr_in( port, '0.0.0.0' ) )
      puts "udpd bound on #{ port } #{ Time.new }"

      udpd_info = {
        udp_addrs: {}, # udp_addr => dest
        dest_ids: {},  # dest_id => dest
        dests: {}      # dest => {
                       #   dest_id: dest_id,
                       #   udp_addr: udp_addr,
                       #   dest_addr: dest_addr,
                       #   last_recv_at: now
                       # }
      }

      @udpd = udpd
      @udpd_info = udpd_info
      @roles[ udpd ] = :udpd
      @infos[ udpd ] = udpd_info
      @reads << udpd

      ctlr, ctlw = IO.pipe
      @ctlw = ctlw
      @roles[ ctlr ] = :ctlr
      @reads << ctlr
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
      dest_id = ctlr.read( 8 ).unpack( 'Q>' ).first
      dest = @udpd_info[ :dest_ids ][ dest_id ]

      if dest
        # puts "debug expire dest #{ dest_id } #{ Time.new }"

        unless @writes.include?( dest )
          @writes << dest
        end
      end
    end

    def read_udpd( udpd )
      data, addrinfo, rflags, *controls = udpd.recvmsg

      info = @infos[ udpd ]
      udp_addr = addrinfo.to_sockaddr
      dest = info[ :udp_addrs ][ udp_addr ]

      unless dest
        dest_addr = data
        return unless Addrinfo.new( dest_addr ).ip?

        dest = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
        dest.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
        dest.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )
        # puts "debug a new dest bound on #{ dest.local_address.ip_unpack.last } #{ Time.new }"

        dest_id = @hex.gen_random_num
        info[ :udp_addrs ][ udp_addr ] = dest
        info[ :dest_ids ][ dest_id ] = dest
        info[ :dests ][ dest ] = {
          dest_id: dest_id,
          udp_addr: udp_addr,
          dest_addr: dest_addr,
          last_recv_at: Time.new
        }

        @roles[ dest ] = :dest
        @reads << dest

        return
      end

      dest_info = info[ :dests ][ dest ]

      begin
        dest.sendmsg( data, 0, dest_info[ :dest_addr ] )
      rescue Errno::EACCES, Errno::EINTR => e
        puts "dest sendmsg #{ e.class } #{ Time.new }"
        @ctlw.write( [ dest_info[ :dest_id ] ].pack( 'Q>' ) )
      end
    end

    def read_dest( dest )
      data, addrinfo, rflags, *controls = dest.recvmsg

      dest_info = @udpd_info[ :dests ][ dest ]
      return unless dest_info

      dest_info[ :last_recv_at ] = Time.new
      @udpd.sendmsg( data, 0, dest_info[ :udp_addr ] )
    end

    def close_dest( dest )
      dest.close
      @reads.delete( dest )
      @writes.delete( dest )
      @roles.delete( dest )
      dest_info = @udpd_info[ :dests ].delete( dest )
      @udpd_info[ :udp_addrs ].delete( dest_info[ :udp_addr ] )
      @udpd_info[ :dest_ids ].delete( dest_info[ :dest_id ] )
    end

    def loop_expire
      Thread.new do
        loop do
          sleep 60

          @mutex.synchronize do
            now = Time.new

            @udpd_info[ :dests ].values.each do | dest_info |
              if now - dest_info[ :last_recv_at ] > 3600
                @ctlw.write( [ dest_info[ :dest_id ] ].pack( 'Q>' ) )
              end
            end
          end
        end
      end
    end

  end
end
