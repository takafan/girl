require 'girl/version'
require 'socket'

##
# Girl::Udp - udp透明转发，近端。
#
# usage
# ======
#
# Girl::Udpd.new( 3030 ).looping # 远端
#
# Girl::Udp.new( 'your.server.ip', 3030, 1313 ).looping # 近端
#
# iptables -t nat -A PREROUTING -p udp -d game.server.ip -j REDIRECT --to-ports 1313
#
module Girl
  class Udp

    def initialize( udpd_host, udpd_port = 3030, redir_port = 1313 )
      @udpd_host = udpd_host
      @udpd_addr = Socket.sockaddr_in( udpd_port, udpd_host )
      @mutex = Mutex.new
      @reads = []
      @writes = []
      @roles = {}        # :dotr / :redir / :tun
      @redir_wbuffs = [] # [ src_addr data ] ...
      @tuns = {}         # [ orig_src_addr dst_addr ]=> tun
      @mappings = {}     # src_addr => [ orig_src_addr dst_addr ]
      @tun_infos = {}    # tun => {}
                         #   orig_src_addr: sockaddr
                         #   dst_addr: sockaddr
                         #   src_addr: sockaddr
                         #   tund_addr: sockaddr
                         #   rbuffs: []
                         #   wbuffs: []
                         #   last_traff_at: now
      dotr, dotw = IO.pipe
      @dotw = dotw
      add_read( dotr, :dotr )
      new_a_redir( redir_port )
    end

    def looping
      loop_expire

      loop do
        rs, ws = IO.select( @reads, @writes )

        @mutex.synchronize do
          ws.each do | sock |
            case @roles[ sock ]
            when :redir then
              write_redir( sock )
            when :tun then
              write_tun( sock )
            end
          end

          rs.each do | sock |
            case @roles[ sock ]
            when :dotr then
              read_dotr( sock )
            when :redir then
              read_redir( sock )
            when :tun then
              read_tun( sock )
            end
          end
        end
      end
    end

    def quit!
      exit
    end

    private

    def loop_expire
      Thread.new do
        loop do
          sleep 30

          @mutex.synchronize do
            trigger = false
            now = Time.new

            @tun_infos.each do | tun, tun_info |
              # net.netfilter.nf_conntrack_udp_timeout_stream
              if now - tun_info[ :last_traff_at ] > 180 then
                set_is_closing( tun )
                trigger = true
              end
            end

            if trigger then
              next_tick
            end
          end
        end
      end
    end

    def new_a_redir( redir_port )
      redir = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      redir.bind( Socket.sockaddr_in( redir_port, '0.0.0.0' ) )
      puts "redir bound on #{ redir_port } #{ Time.new }"
      @redir = redir
      add_read( redir, :redir )
    end

    def new_a_tun( orig_src_addr, dst_addr, src_addr )
      tun = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      tun.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      tun.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )

      @tun_infos[ tun ] = {
        orig_src_addr: orig_src_addr,
        dst_addr: dst_addr,
        src_addr: src_addr,
        tund_addr: nil,
        rbuffs: [],
        wbuffs: [],
        last_traff_at: Time.new,
        is_closing: false
      }

      @tuns[ [ orig_src_addr, dst_addr ].join ] = tun
      add_read( tun, :tun )

      tun
    end

    def add_redir_wbuff( redir, to_addr, data )
      @redir_wbuffs << [ to_addr, data ]
      add_write( redir )
    end

    def add_tun_wbuff( tun, to_addr, data )
      tun_info = @tun_infos[ tun ]

      if to_addr then
        tun_info[ :wbuffs ] << [ to_addr, data ]
        add_write( tun )
      else
        tun_info[ :rbuffs ] << data
      end
    end

    def add_read( sock, role )
      unless @reads.include?( sock ) then
        @reads << sock
      end

      @roles[ sock ] = role
    end

    def add_write( sock )
      unless @writes.include?( sock ) then
        @writes << sock
      end
    end

    def set_is_closing( tun )
      if tun && !tun.closed? then
        # puts "debug1 set tun is closing"

        tun_info = @tun_infos[ tun ]
        tun_info[ :is_closing ] = true

        @reads.delete( tun )
        add_write( tun )
      end
    end

    def send_data( sock, data, to_addr )
      begin
        sock.sendmsg( data, 0, to_addr )
      rescue IO::WaitWritable, Errno::EINTR
        return false
      rescue Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ENETDOWN => e
        if @roles[ sock ] == :tun then
          puts "#{ Time.new } #{ e.class }, close tun"
          close_tun( sock )
          return false
        end
      end

      true
    end

    def close_tun( tun )
      tun.close
      @reads.delete( tun )
      @writes.delete( tun )
      @roles.delete( tun )
      tun_info = @tun_infos.delete( tun )
      @tuns.delete( [ tun_info[ :orig_src_addr ], tun_info[ :dst_addr ] ].join )

      if @mappings.include?( tun_info[ :src_addr ] ) then
        orig_src_addr, dst_addr, timeout, read_at = @mappings[ tun_info[ :src_addr ] ]

        if orig_src_addr == tun_info[ :orig_src_addr ] && dst_addr == tun_info[ :dst_addr ] then
          @mappings.delete( tun_info[ :src_addr ] )
        end
      end
    end

    def write_redir( redir )
      while @redir_wbuffs.any? do
        to_addr, data = @redir_wbuffs.first

        return unless send_data( redir, data, to_addr )

        @redir_wbuffs.shift
      end

      @writes.delete( redir )
    end

    def write_tun( tun )
      tun_info = @tun_infos[ tun ]

      if tun_info[ :is_closing ] then
        close_tun( tun )
        return
      end

      while tun_info[ :wbuffs ].any? do
        to_addr, data = tun_info[ :wbuffs ].first

        unless send_data( tun, data, to_addr ) then
          return
        end

        tun_info[ :wbuffs ].shift
      end

      @writes.delete( tun )
    end

    def read_dotr( dotr )
      dotr.read( 1 )
    end

    def read_redir( redir )
      data, addrinfo, rflags, *controls = redir.recvmsg
      src_addr = addrinfo.to_sockaddr
      is_hit_cache = false
      now = Time.new
      # puts "debug redir recv #{ data.inspect } from #{ addrinfo.inspect }"

      if @mappings.include?( src_addr ) then
        orig_src_addr, dst_addr, timeout, read_at = @mappings[ src_addr ]

        if now - read_at < timeout then
          # puts "debug hit cache #{ addrinfo.inspect }"
          is_hit_cache = true
        else
          # puts "debug cache timeout #{ addrinfo.inspect }"
          @mappings.delete( src_addr )
        end
      end

      unless is_hit_cache then
        # 2 udp 4 timeout 5 src 7 sport 9 [UNREPLIED] 11 dst 13 dport
        # 2 udp 4 timeout 5 src 7 sport 10 dst 12 dport
        bin = IO.binread( '/proc/net/nf_conntrack' )
        rows = bin.split( "\n" ).map { | line | line.split( ' ' ) }
        row = rows.find { | _row | _row[ 2 ] == 'udp' && ( ( _row[ 10 ].split( '=' )[ 1 ] == addrinfo.ip_address && _row[ 12 ].split( '=' )[ 1 ].to_i == addrinfo.ip_port ) || ( _row[ 9 ] == '[UNREPLIED]' && _row[ 11 ].split( '=' )[ 1 ] == addrinfo.ip_address && _row[ 13 ].split( '=' )[ 1 ].to_i == addrinfo.ip_port ) ) }

        unless row then
          puts "miss conntrack #{ addrinfo.inspect } #{ Time.new }"
          IO.binwrite( '/tmp/nf_conntrack', bin )
          return
        end

        timeout = row[ 4 ].to_i
        orig_src_ip = row[ 5 ].split( '=' )[ 1 ]
        orig_src_port = row[ 7 ].split( '=' )[ 1 ].to_i
        dst_ip = row[ 6 ].split( '=' )[ 1 ]
        dst_port = row[ 8 ].split( '=' )[ 1 ].to_i
        orig_src_addr = Socket.sockaddr_in( orig_src_port, orig_src_ip )
        dst_addr = Socket.sockaddr_in( dst_port, dst_ip )

        if Addrinfo.new( dst_addr ).ipv4_private? then
          puts "dst is private? #{ Addrinfo.new( dst_addr ).inspect } #{ Addrinfo.new( src_addr ).inspect } #{ Addrinfo.new( orig_src_addr ).inspect } #{ Time.new }"
          add_redir_wbuff( redir, dst_addr, data )
          return
        end

        # puts "debug save cache #{ addrinfo.inspect } #{ Addrinfo.new( orig_src_addr ).inspect } #{ Addrinfo.new( dst_addr ).inspect } #{ timeout } #{ now }"
        @mappings[ src_addr ] = [ orig_src_addr, dst_addr, timeout, now ]
      end

      tun = @tuns[ [ orig_src_addr, dst_addr ].join ]

      unless tun then
        tun = new_a_tun( orig_src_addr, dst_addr, src_addr )

        # puts "debug tun send to udpd #{ Addrinfo.new( orig_src_addr ).inspect } #{ Addrinfo.new( dst_addr ).inspect }"
        ctlmsg = [ orig_src_addr, dst_addr ].join
        add_tun_wbuff( tun, @udpd_addr, ctlmsg )
      end

      tun_info = @tun_infos[ tun ]
      add_tun_wbuff( tun, tun_info[ :tund_addr ], data )
    end

    def read_tun( tun )
      data, addrinfo, rflags, *controls = tun.recvmsg
      from_addr = addrinfo.to_sockaddr
      tun_info = @tun_infos[ tun ]
      tun_info[ :last_traff_at ] = Time.new

      if from_addr == @udpd_addr then
        tund_port = data[ 0, 2 ].unpack( 'n' ).first
        tund_addr = Socket.sockaddr_in( tund_port, @udpd_host )
        tun_info[ :tund_addr ] = tund_addr

        if tun_info[ :rbuffs ].any? then
          tun_info[ :wbuffs ] += tun_info[ :rbuffs ].map{ | rbuff | [ tund_addr, rbuff ] }
          tun_info[ :rbuffs ].clear
          add_write( tun )
        end

      elsif from_addr == tun_info[ :tund_addr ] then
        add_redir_wbuff( @redir, tun_info[ :src_addr ], data )
      end
    end

  end
end
