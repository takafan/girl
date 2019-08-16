require 'girl/hex'
require 'girl/version'
require 'socket'

##
# Girl::Resolv - dns查询得到正确的ip。近端。
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
      @reads = []
      @writes = []
      @socks = {} # object_id => sock
      @roles = {} # sock => :ctlr / :redir / :resolv / :pub
      @infos = {} # redir => {}
      @hex = Girl::Hex.new
      @mutex = Mutex.new

      redir = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      redir.bind( Socket.sockaddr_in( port, '0.0.0.0' ) )
      puts "redir bound on #{ port } #{ Time.new }"

      nameservers = nameservers.select{ | ns | Addrinfo.udp( ns, 53 ).ipv4? }

      if nameservers.empty?
        nameservers = %w[ 114.114.114.114 114.114.115.115 ]
      end

      redir_info = {
        src_addrs: {},       # src_addr => resolv_or_pub
        socks: {},           # resolv_or_pub => src_addr
        last_coming_ats: {}, # resolv_or_pub => now
        caches: {},          # question => [ cache, ttl_ix, expire ]
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
      sock = @socks[ sock_id ]

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
      qname = data[ 12, qname_len ]
      question = data[ 12, qname_len + 5 ]
      cache, ttl_ix, expire = info[ :caches ][ question ]

      if cache
        if expire > now
          cache[ 0, 2 ] = id
          cache[ ttl_ix, 4 ] = [ ( expire - now ).to_i ].pack( 'N' )
          # puts "debug send cache #{ Time.new }"
          redir.sendmsg( cache, 0, src_addr )
          return
        else
          info[ :caches ].delete( question )
        end
      end

      sock = info[ :src_addrs ][ src_addr ]

      unless sock
        sock = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
        sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
        sock.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )

        @socks[ sock.object_id ] = sock

        if info[ :resolvd_addr ] && ( info[ :custom_qnames ].any? { | custom | qname.include?( custom ) } )
          @roles[ sock ] = :resolv
        else
          @roles[ sock ] = :pub
        end

        # puts "debug a new #{ @roles[ sock ] } bound on #{ sock.local_address.ip_unpack.last } #{ Time.new }"

        @reads << sock
        info[ :src_addrs ][ src_addr ] = sock
        info[ :socks ][ sock ] = src_addr
        info[ :last_coming_ats ][ sock ] = now
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

      qname_len = data[ 12..-1 ].index([ 0 ].pack( 'C' ))
      return unless qname_len

      src_addr = @redir_info[ :socks ][ sock ]
      return unless src_addr

      now = Time.new
      @redir_info[ :last_coming_ats ][ sock ] = now
      @redir.sendmsg( data, 0, src_addr )

      ancount = data[ 6, 2 ].unpack( 'n' ).first
      nscount = data[ 8, 2 ].unpack( 'n' ).first
      qname = data[ 12, qname_len ]
      return if ancount == 0 && nscount == 0

      # move to first RR = Header (12) + QNAME + 0x00 + QTYPE (2) + QCLASS (2)
      ix = 17 + qname_len
      ttls = []

      ( ancount + nscount ).times do | i |
        unless data[ ix ]
          puts "nil answer? #{ i } of #{ ancount + nscount } RR #{ data.inspect } #{ Time.new }"
          break
        end

        loop do
          if data[ ix ].unpack( 'B8' ).first[ 0, 2 ] == '11' # pointer
            # move to TTL
            ix += 6
            break
          else
            len = data[ ix ].unpack( 'C' ).first
            if len == 0
              # move to TTL
              ix += 5
              break
            end
            # move to next label
            ix += ( len + 1 )
          end
        end

        ttls << [ ix, now + data[ ix, 4 ].unpack( 'N' ).first ]

        # move to next RR = TTL(4) + RDLENGTH(2) + RDATA
        ix += ( 6 + data[ ix + 4, 2 ].unpack( 'n' ).first )
      end

      return if ttls.empty?

      # cache data and set expire by shortest TTL
      question = qname + data[ 12 + qname_len, 5 ]
      @redir_info[ :caches ][ question ] = [ data, *ttls.sort_by{ | _, exp | exp }.first ]
    end

    def close_sock( sock )
      sock.close
      @reads.delete( sock )
      @writes.delete( sock )
      @socks.delete( sock.object_id )
      @roles.delete( sock )
      @redir_info[ :last_coming_ats ].delete( sock )
      src_addr = @redir_info[ :socks ].delete( sock )
      @redir_info[ :src_addrs ].delete( src_addr )
    end

    def loop_expire
      Thread.new do
        loop do
          sleep 10

          @mutex.synchronize do
            now = Time.new
            socks = @redir_info[ :socks ].keys

            socks.each do | sock |
              if now - @redir_info[ :last_coming_ats ][ sock ] > 30
                @ctlw.write( [ sock.object_id ].pack( 'Q>' ) )
              end
            end
          end
        end
      end
    end

  end
end
