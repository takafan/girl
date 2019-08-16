require 'girl/hex'
require 'girl/version'
require 'socket'

##
# Girl::Resolvd - dns查询得到正确的ip。远端。
#
module Girl
  class Resolvd

    def initialize( port = 7070, nameservers = [] )
      @reads = []
      @writes = []
      @socks = {} # object_id => sock
      @roles = {} # sock => :ctlr / :resolvd / :pub
      @infos = {} # resolvd => {}
      @hex = Girl::Hex.new
      @mutex = Mutex.new

      resolvd = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      resolvd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      resolvd.bind( Socket.sockaddr_in( port, '0.0.0.0' ) )
      puts "resolvd bound on #{ port } #{ Time.new }"

      nameservers = nameservers.select{ | ns | Addrinfo.udp( ns, 53 ).ipv4? }

      resolvd_info = {
        resolv_addrs: {},    # resolv_addr => pub
        pubs: {},            # pub => src_addr
        last_coming_ats: {}, # pub => now
        pubd_addrs: nameservers.map{ | ns | Socket.sockaddr_in( 53, ns ) }
      }

      @resolvd = resolvd
      @resolvd_info = resolvd_info
      @roles[ resolvd ] = :resolvd
      @infos[ resolvd ] = resolvd_info
      @reads << resolvd

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
            when :resolvd
              read_resolvd( sock )
            when :pub
              read_pub( sock )
            end
          end

          ws.each do | sock |
            close_sock( sock )
          end
        end
      end
    end

    def quit!
      exit
    end

    private

    def read_ctlr( ctlr )
      sock_id = ctlr.read( 8 ).unpack( 'Q>' ).first
      sock = @socks[ sock_id ]

      if sock
        # puts "debug expire pub #{ sock_id } #{ Time.new }"

        unless @writes.include?( sock )
          @writes << sock
        end
      end
    end

    def read_resolvd( resolvd )
      data, addrinfo, rflags, *controls = resolvd.recvmsg
      return if data.size <= 12

      data = @hex.decode( data )
      info = @infos[ resolvd ]
      resolv_addr = addrinfo.to_sockaddr
      pub = info[ :resolv_addrs ][ resolv_addr ]

      unless pub
        pub = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
        pub.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
        pub.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )
        # puts "debug a new pub bound on #{ pub.local_address.ip_unpack.last } #{ Time.new }"

        @socks[ pub.object_id ] = pub
        @roles[ pub ] = :pub
        @reads << pub
        info[ :resolv_addrs ][ resolv_addr ] = pub
        info[ :pubs ][ pub ] = resolv_addr
        info[ :last_coming_ats ][ pub ] = Time.new
      end

      info[ :pubd_addrs ].each do | pubd_addr |
        pub.sendmsg( data, 0, pubd_addr )
      end
    end

    def read_pub( pub )
      data, addrinfo, rflags, *controls = pub.recvmsg
      return if data.size <= 12

      resolv_addr = @resolvd_info[ :pubs ][ pub ]
      return unless resolv_addr

      # puts "debug pub recvmsg #{ data.inspect }"
      @resolvd_info[ :last_coming_ats ][ pub ] = Time.new
      data = @hex.encode( data )
      # puts "debug resolvd sendmsg #{ data.inspect }"
      @resolvd.sendmsg( data, 0, resolv_addr )
    end

    def close_sock( sock )
      sock.close
      @reads.delete( sock )
      @writes.delete( sock )
      @socks.delete( sock.object_id )
      @roles.delete( sock )
      @resolvd_info[ :last_coming_ats ].delete( sock )
      resolv_addr = @resolvd_info[ :pubs ].delete( sock )
      @resolvd_info[ :resolv_addrs ].delete( resolv_addr )
    end

    def loop_expire
      Thread.new do
        loop do
          sleep 10

          @mutex.synchronize do
            now = Time.new
            pubs = @resolvd_info[ :pubs ].keys

            pubs.each do | pub |
              if now - @resolvd_info[ :last_coming_ats ][ pub ] > 30
                @ctlw.write( [ pub.object_id ].pack( 'Q>' ) )
              end
            end
          end
        end
      end
    end

  end
end
