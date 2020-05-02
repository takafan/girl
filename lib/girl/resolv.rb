require 'girl/hex'
require 'girl/version'
require 'socket'

##
# Girl::Resolv - dns查询得到正确的ip，近端。
#
# usage
# =====
#
# Girl::Resolvd.new( 7070 ).looping # 远端
#
# Girl::Resolv.new( 1717, [ '114.114.114.114' ], 'your.server.ip', 7070, [ 'google.com' ] ).looping # 近端
#
# dig google.com @127.0.0.1 -p1717
#
module Girl
  class Resolv

    def initialize( port = 1717, nameservers = [], resolvd_host = nil, resolvd_port = nil, custom_domains = [] )
      @hex = Girl::Hex.new
      @mutex = Mutex.new
      @reads = []
      @writes = []
      @roles = {} # sock => :ctlr / :redir / :resolv / :pub
      @infos = {} # redir => {}
      @socks = {} # sock => sock_id
      @sock_ids = {} # sock_id => sock

      redir = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      redir.bind( Socket.sockaddr_in( port, '0.0.0.0' ) )
      puts "redir bound on #{ port } #{ Time.new }"

      nameservers = nameservers.select{ | ns | Addrinfo.udp( ns, 53 ).ipv4? }

      if nameservers.empty?
        nameservers = %w[ 114.114.114.114 114.114.115.115 ]
      end

      redir_info = {
        src_addrs: {},     # src_addr => resolv_or_pub
        socks: {},         # resolv_or_pub => src_addr
        last_recv_ats: {}, # resolv_or_pub => now
        pubd_addrs: nameservers.map{ | ns | Socket.sockaddr_in( 53, ns ) },
        resolvd_addr: ( resolvd_host && resolvd_port ) ? Socket.sockaddr_in( resolvd_port, resolvd_host ) : nil,
        custom_qnames: custom_domains.map{ | dom | dom.split( '.' ).map{ | sub | [ sub.size ].pack( 'C' ) + sub }.join }
      }

      @redir = redir
      @redir_info = redir_info
      @roles[ redir ] = :redir
      @infos[ redir ] = redir_info
      @reads << redir

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
            when :redir
              read_redir( sock )
            when :resolv, :pub
              read_sock( sock )
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
      sock = @sock_ids[ sock_id ]

      if sock
        # puts "debug expire #{ @roles[ sock ] } #{ sock_id } #{ Time.new }"

        unless @writes.include?( sock )
          @writes << sock
        end
      end
    end

    def read_redir( redir )
      # https://tools.ietf.org/html/rfc1035#page-26
      data, addrinfo, rflags, *controls = redir.recvmsg
      return if data.size <= 12

      id = data[ 0, 2 ]
      qname_len = data[ 12..-1 ].index( [ 0 ].pack( 'C' ) )
      return unless qname_len

      now = Time.new
      info = @infos[ redir ]
      src_addr = addrinfo.to_sockaddr
      sock = info[ :src_addrs ][ src_addr ]

      unless sock
        sock = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
        sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
        sock.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )

        sock_id = @hex.gen_random_num
        @socks[ sock ] = sock_id
        @sock_ids[ sock_id ] = sock
        qname = data[ 12, qname_len ]

        if info[ :resolvd_addr ] && ( info[ :custom_qnames ].any? { | custom | qname.include?( custom ) } )
          @roles[ sock ] = :resolv
        else
          @roles[ sock ] = :pub
        end

        # puts "debug a new #{ @roles[ sock ] } bound on #{ sock.local_address.ip_unpack.last } #{ Time.new }"

        @reads << sock
        info[ :src_addrs ][ src_addr ] = sock
        info[ :socks ][ sock ] = src_addr
        info[ :last_recv_ats ][ sock ] = now
      end

      if @roles[ sock ] == :resolv
        data = @hex.encode( data )
        sock.sendmsg( data, 0, info[ :resolvd_addr ] )
      else
        info[ :pubd_addrs ].each { | pubd_addr | sock.sendmsg( data, 0, pubd_addr ) }
      end
    end

    def read_sock( sock )
      data, addrinfo, rflags, *controls = sock.recvmsg
      return if data.size <= 12

      if @roles[ sock ] == :resolv
        data = @hex.decode( data )
      end

      src_addr = @redir_info[ :socks ][ sock ]
      return unless src_addr

      @redir_info[ :last_recv_ats ][ sock ] = Time.new
      @redir.sendmsg( data, 0, src_addr )
    end

    def close_sock( sock )
      sock.close
      @reads.delete( sock )
      @writes.delete( sock )
      @roles.delete( sock )
      sock_id = @socks.delete( sock )
      @sock_ids.delete( sock_id )
      @redir_info[ :last_recv_ats ].delete( sock )
      src_addr = @redir_info[ :socks ].delete( sock )
      @redir_info[ :src_addrs ].delete( src_addr )
    end

    def loop_expire
      Thread.new do
        loop do
          sleep 60

          @mutex.synchronize do
            now = Time.new
            socks = @redir_info[ :socks ].keys

            socks.each do | sock |
              if now - @redir_info[ :last_recv_ats ][ sock ] > 5
                sock_id = @socks[ sock ]
                @ctlw.write( [ sock_id ].pack( 'Q>' ) )
              end
            end
          end
        end
      end
    end

  end
end
