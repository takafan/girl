##
# usage
# =====
#
# 1. Girl::Relayd.new( 8080 ).looping # @server
#
# 2. Girl::Redir.new( 1919, 'your.server.ip', 8080 ).looping # @home
#
# 3. dig www.google.com @127.0.0.1 -p1818 # dig with girl/resolv, got 216.58.217.196
#
# 4. iptables -A OUTPUT -p tcp -d 216.58.217.196 -j REDIRECT --to-ports 1919
#
# 5. curl https://www.google.com/
#
require 'girl/hex'
require 'socket'

module Girl
  class Redir

    def initialize( redir_port, relayd_host, relayd_port, hex_block = nil, chunk_dir = '/tmp/redir' )
      if hex_block
        Girl::Hex.class_eval( hex_block )
      end

      unless Dir.exist?( chunk_dir )
        Dir.mkdir( chunk_dir )
      end

      @reads = [] # socks
      @writes = {} # sock => :buff / :cache
      @buffs = {} # sock => 4M working ram
      @caches = {} # sock => the left data of first chunk
      @chunks = {} # sock => { seed: 0, files: [ /tmp/relayd/{pid}-{object_id}.0, ... ] }
      @roles = {} # :redir / :source / :relay
      @timestamps = {} # source / relay => last r/w
      @twins = {} # source <=> relay
      @relayd_sockaddr = Socket.sockaddr_in( relayd_port, relayd_host )
      @hex = Girl::Hex.new
      @chunk_dir = chunk_dir

      redir = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      redir.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      redir.bind( Socket.pack_sockaddr_in( redir_port, '0.0.0.0' ) )
      redir.listen( 128 )
      puts "p#{ Process.pid } listening on #{ redir_port }"

      @reads << redir
      @roles[ redir ] = :redir
    end

    def looping
      loop do
        readable_socks, writable_socks = IO.select( @reads, @writes.keys )

        readable_socks.each do | sock |
          case @roles[ sock ]
          when :redir
            now = Time.new
            print "p#{ Process.pid } #{ now } "

            @timestamps.select{ | _, stamp | now - stamp > 600 }.each do | so, _ |
              close_socket( so )
            end

            begin
              source, _ = sock.accept_nonblock
            rescue IO::WaitReadable, Errno::EINTR
              next
            rescue Errno::EMFILE => e
              puts e.class
              quit!
            end

            begin
              # SO_ORIGINAL_DST
              # https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter_ipv4.h
              dst_addr = source.getsockopt( Socket::SOL_IP, 80 )
            rescue Exception => e
              puts "get SO_ORIGINAL_DST #{ e.class }"
              source.close
              next
            end

            dst_family, dst_port, dst_host = dst_addr.unpack( 'nnN' )
            relay = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
            relay.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )

            begin
              relay.connect_nonblock( @relayd_sockaddr )
            rescue IO::WaitWritable, Errno::EINTR
            rescue Exception => e
              puts "connect relayd #{ e.class }"
              relay.close
              next
            end

            @reads << source
            @roles[ source ] = :source
            @buffs[ source ] = ''
            @chunks[ source ] = { seed: 0, files: [] }
            @timestamps[ source ] = now
            @twins[ source ] = relay

            @reads << relay
            @roles[ relay ] = :relay
            @buffs[ relay ] = ''
            @chunks[ relay ] = { seed: 0, files: [] }
            @timestamps[ relay ] = now
            @twins[ relay ] = source

            buffer( relay, @hex.swap( @hex.mix( dst_host, dst_port ) ) )
          when :source
            relay = @twins[ sock ]

            if relay.closed?
              close_socket( sock )
              next
            end

            begin
              data = sock.read_nonblock( 4096 )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e # WaitWritable for SSL renegotiation
              next
            rescue Exception => e
              close_socket( sock )
              next
            end

            @timestamps[ sock ] = Time.new
            buffer( relay, @hex.swap( data ) )
          when :relay
            source = @twins[ sock ]

            if source.closed?
              close_socket( sock )
              next
            end

            begin
              data = @hex.swap( sock.read_nonblock( 4096 ) )
            rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e  # WaitWritable for SSL renegotiation
              next
            rescue Exception => e
              close_socket( sock )
              next
            end

            @timestamps[ sock ] = Time.new
            buffer( source, data )
          end
        end

        writable_socks.each do | sock |
          if sock.closed?
            next
          end

          if @writes[ sock ] == :buff
            data = @buffs[ sock ]
          else
            unless @caches[ sock ]
              @caches[ sock ] = IO.binread( @chunks[ sock ][ :files ][ 0 ] )
            end

            data = @caches[ sock ]
          end

          begin
            written = sock.write_nonblock( data )
          rescue IO::WaitWritable, Errno::EINTR, IO::WaitReadable => e # WaitReadable for SSL renegotiation
            next
          rescue Exception => e
            close_socket( sock )
            next
          end

          @timestamps[ sock ] = Time.new
          data = data[ written..-1 ]

          if @writes[ sock ] == :buff
            @buffs[ sock ] = data

            if data.empty?
              @writes.delete( sock )
            end
          else
            if data.empty?
              @caches.delete( sock )

              begin
                File.delete( @chunks[ sock ][ :files ].shift )
              rescue Errno::ENOENT
              end

              if @chunks[ sock ][ :files ].empty?
                if @buffs[ sock ].empty?
                  @writes.delete( sock )
                else
                  @writes[ sock ] = :buff
                end
              end
            else
              @caches[ sock ] = data
            end
          end
        end
      end
    end

    def quit!
      @reads.each{ | sock | sock.close }
      @chunks.each do | sock, chunk |
        chunk[ :files ].each do | path |
          begin
            File.delete( path )
          rescue Errno::ENOENT
          end
        end
      end

      @reads.clear
      @writes.clear
      @buffs.clear
      @caches.clear
      @chunks.clear
      @roles.clear
      @timestamps.clear
      @twins.clear

      exit
    end

    private

    def buffer( sock, data )
      @buffs[ sock ] << data
      @timestamps[ sock ] = Time.new

      if @writes[ sock ].nil?
        @writes[ sock ] = :buff
      elsif @buffs[ sock ].size >= 4194304
        chunk_path = File.join( @chunk_dir, "#{ Process.pid }-#{ sock.object_id }.#{ @chunks[ sock ][ :seed ] }" )
        File.open( chunk_path, 'w' ){ | f | f.print @buffs[ sock ] }
        @chunks[ sock ][ :files ] << chunk_path
        @chunks[ sock ][ :seed ] += 1
        @writes[ sock ] = :cache
        @buffs[ sock ] = ''
      end
    end

    def close_socket( sock )
      sock.close
      @chunks[ sock ][ :files ].each do | path |
        begin
          File.delete( path )
        rescue Errno::ENOENT
        end
      end

      @reads.delete( sock )
      @writes.delete( sock )
      @buffs.delete( sock )
      @caches.delete( sock )
      @chunks.delete( sock )
      @roles.delete( sock )
      @timestamps.delete( sock )
      @twins.delete( sock )
    end

  end
end
