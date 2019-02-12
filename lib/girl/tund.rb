require 'girl/hex'
require 'nio'
require 'socket'

##
# Girl::Tund
#
# tcp流量正常的到达目的地。
#
# infos，存取sock信息，根据角色，sock => {}：
#
# {
#   role: :tund,
#   mon: mon,
#   wbuff: '',
#   cache: '',
#   filename: '',
#   chunk_dir: '',
#   chunks: [],
#   chunk_seed: 0,
#   ctls: [],
#   memories: { pack_id => [ '', now, 0 ] },
#   tun_addr: tun_addr,
#   dests: { dest_id => [ dest, source_id ] },
#   pairs: { source_id => dest },
#   dest_fins: { pack_id => 1 }
# }
#
# {
#   role: :dest,
#   mon: mon,
#   wbuff: '',
#   cache: '',
#   filename: '',
#   chunk_dir: '',
#   chunks: [],
#   chunk_seed: 0,
#   id: '',
#   pcur: 0
#   source_pcur: 0,
#   pieces: { 2 => '', 4 => '' },
#   source_fin: [ 1, 1024 ],
#   tund: tund
# }
#
# role          角色，:roomd / :dest / :tund
# mon           NIO::Monitor
# wbuff         写前缓存
# cache         块缓存
# filename      [ Process.pid, sock.object_id ].join( '-' )
# chunk_dir     块目录
# chunks        块文件名，wbuff每超过1.4M落一个块
# chunk_seed    块序号
# ctls          ctl缓存。写的时候，先取ctl，ctls为空，取cache，cache为空，取一个chunk放进cache，chunks为空，取wbuff。
# memories      写后缓存
# tun_addr      另一头地址
# dests         根据dest_id，取dest和source_id
# pairs         根据source_id，取dest
# dest_fins     dest读到异常后，记关闭标记在tund身上，紧跟最后一个流量包，发送“dest已关闭”。
# id            [ Process.pid, dest.object_id ].pack( 'nn' )
# pcur          打包光标
# source_pcur   写前光标
# pieces        跳号缓存
# source_fin    远端传来“source已关闭”，记在dest身上，传完所有流量后关闭dest。
#
module Girl
  PACK_SIZE = 1456 # 1492(PPPoE MTU) - 20(IPv4 head) - 8(UDP head) - 8(pack id) = 1456
  CHUNK_SIZE = PACK_SIZE * 1000
  MEMORIES_LIMIT = 10_000 # 写后缓存上限
  RESEND_LIMIT = 20 # 重传次数上限

  class Tund
    def initialize( roomd_port = 9090, dest_chunk_dir = '/tmp', tund_chunk_dir = '/tmp' )
      selector = NIO::Selector.new
      roomd = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      roomd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      roomd.bind( Socket.pack_sockaddr_in( roomd_port, '0.0.0.0' ) )
      roomd_info = {
        role: :roomd,
        mon: selector.register( roomd, :r ),
        clients: {} # sockaddr => [ tund, now ]
      }

      @dest_chunk_dir = dest_chunk_dir
      @tund_chunk_dir = tund_chunk_dir
      @hex = Girl::Hex.new
      @mutex = Mutex.new
      @selector = selector
      @roomd_info = roomd_info
      @infos = {
        roomd => roomd_info
      }
    end

    def looping
      puts 'looping'
      # 关闭过期的通道
      expire_clients
      # 重传
      loop_resend

      loop do
        @selector.select do | mon |
          sock = mon.io

          if sock.closed?
            puts 'sock already closed'
            next
          end

          info = @infos[ sock ]

          if mon.readable?
            case info[ :role ]
            when :roomd
              data, addrinfo, rflags, *controls = sock.recvmsg
              result = @hex.check( data, addrinfo )

              if result != :success
                puts result
                next
              end

              if info[ :clients ].include?( addrinfo.to_sockaddr )
                puts "tunnel already exist #{ addrinfo.ip_unpack.inspect }"
                next
              end

              tund = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
              tund.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )

              @infos[ tund ] = {
                role: :tund,
                mon: @selector.register( tund, :r ),
                wbuff: '',
                cache: '',
                filename: [ Process.pid, tund.object_id ].join( '-' ),
                chunk_dir: @tund_chunk_dir,
                chunks: [],
                chunk_seed: 0,
                ctls: [],
                memories: {},
                tun_addr: addrinfo,
                dests: {},
                dest_fins: {},
                pairs: {}
              }

              tund_port  = tund.local_address.ip_unpack.last
              pack = [ tund_port ].pack( 'n' )
              sock.sendmsg( pack, 0, addrinfo )
              now = Time.new
              info[ :clients ][ addrinfo.to_sockaddr ] = [ tund, now ]
              puts "client #{ addrinfo.ip_unpack.inspect } tund #{ tund_port } #{ now } p#{ Process.pid } #{ info[ :clients ].size }"
            when :dest
              begin
                data = sock.read_nonblock( PACK_SIZE )
              rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
                next
              rescue Exception => e
                err = e.is_a?( EOFError ) ? 1 : 2
                close_dest( sock, err )
                next
              end

              if info[ :tund ].closed?
                close_dest( sock )
                next
              end

              tund_info = @infos[ info[ :tund ] ]
              pcur = info[ :pcur ] + 1

              if pcur == 1
                data = @hex.swap( data )
              end

              data = [ [ data.bytesize, pcur ].pack( 'nN' ), info[ :id ], data ].join
              add_buff( tund_info, data )
              info[ :pcur ] = pcur
            when :tund
              data, addrinfo, rflags, *controls = sock.recvmsg
              source_pcur = data[ 0, 4 ].unpack( 'N' ).first

              if source_pcur == 0
                ctl_num = data[ 4 ].unpack( 'C' ).first

                case ctl_num
                when 1
                  # 1 heartbeat
                  client_info = @roomd_info[ :clients ][ addrinfo.to_sockaddr ]

                  unless client_info
                    puts "unknown client? #{ addrinfo.ip_unpack.inspect }"
                    next
                  end

                  client_info[ 1 ] = Time.new
                when 2
                  # 2 a new source -> nn: source_id -> nnN: dst_family dst_port dst_ip
                  source_id = data[ 5, 4 ]
                  dst_family, dst_port, dst_host = data[ 9, 8 ].unpack( 'nnN' )
                  dest = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
                  dest.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )

                  begin
                    dest.connect_nonblock( Socket.sockaddr_in( dst_port, dst_host ) )
                  rescue IO::WaitWritable, Errno::EINTR
                  rescue Exception => e
                    puts "connect to destination #{ e.class }"
                    dest.close
                    next
                  end

                  dest_id = [ Process.pid, dest.object_id ].pack( 'nn' )
                  info[ :dests ][ dest_id ] = [ dest, source_id ]
                  info[ :pairs ][ source_id ] = dest
                  puts "dest #{ dst_port } #{ dst_host } p#{ Process.pid } #{ info[ :dests ].size }"

                  @infos[ dest ] = {
                    role: :dest,
                    mon: @selector.register( dest, :r ),
                    wbuff: '',
                    cache: '',
                    filename: [ Process.pid, dest.object_id ].join( '-' ),
                    chunk_dir: @dest_chunk_dir,
                    chunks: [],
                    chunk_seed: 0,
                    id: dest_id,
                    pieces: {},
                    pcur: 0,
                    source_pcur: 0,
                    source_fin: nil,
                    tund: sock
                  }

                  ctl = [ [ 3 ].pack( 'C' ), source_id, dest_id ].join
                  add_ctl( info, ctl )
                when 4
                  # 4 confirm a pack -> Nnn: pack_id
                  pack_id = data[ 5, 8 ]
                  memory = info[ :memories ].delete( pack_id )

                  if memory
                    info[ :dest_fins ].delete( pack_id )
                    info[ :mon ].add_interest( :w )
                  end
                when 6
                  # 6 source fin -> C: :eof/:rst -> Nnn: last_pack_id
                  err = data[ 5 ].unpack( 'C' ).first
                  last_pack_id = data[ 6, 8 ]
                  last_source_pcur = last_pack_id[ 0, 4 ].unpack( 'N' ).first
                  source_id = last_pack_id[ 4, 4 ]
                  dest = info[ :pairs ][ source_id ]

                  if dest.nil? || dest.closed?
                    next
                  end

                  dest_info = @infos[ dest ]
                  dest_info[ :source_fin ] = [ err, last_source_pcur ]
                  dest_info[ :mon ].add_interest( :w )
                when 8
                  # 8 tun fin
                  @mutex.synchronize do
                    close_sock( sock )
                    @roomd_info[ :clients ].delete( addrinfo.to_sockaddr )
                  end
                end

                next
              end

              pack_id = data[ 0, 8 ]
              ctl = [ [ 4 ].pack( 'C' ), pack_id ].join
              add_ctl( info, ctl )

              source_id = pack_id[ 4, 4 ]
              dest = info[ :pairs ][ source_id ]

              if dest.nil? || dest.closed?
                next
              end

              dest_info = @infos[ dest ]

              if source_pcur <= dest_info[ :source_pcur ]
                next
              end

              data = data[ 8..-1 ]

              # 解混淆
              if source_pcur == 1
                data = @hex.swap( data )
              end

              # 放进dest的写前缓存，跳号放碎片缓存
              if source_pcur - dest_info[ :source_pcur ] == 1
                while dest_info[ :pieces ].include?( source_pcur + 1 )
                  data << dest_info[ :pieces ].delete( source_pcur + 1 )
                  source_pcur += 1
                end

                add_buff( dest_info, data )
                dest_info[ :source_pcur ] = source_pcur
              else
                dest_info[ :pieces ][ source_pcur ] = data
              end
            end
          end

          if mon.writable?
            case info[ :role ]
            when :dest
              data, from = get_buff( info )

              if data.empty?
                # 有关闭标记，且流量已收全，关闭dest
                if info[ :source_fin ]
                  err, last_source_pcur = info[ :source_fin ]

                  if last_source_pcur == info[ :source_pcur ]
                    if err == 2
                      sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
                    end

                    close_dest( sock, err )
                    next
                  end
                end

                mon.remove_interest( :w )
                next
              end

              begin
                written = sock.write_nonblock( data )
              rescue IO::WaitWritable, Errno::EINTR, IO::WaitReadable => e
                next
              rescue Exception => e
                err = e.is_a?( EOFError ) ? 1 : 2
                close_dest( sock, err )
                next
              end

              data = data[ written..-1 ]

              if from == :cache
                info[ :cache ] = data
              elsif from == :wbuff
                info[ :wbuff ] = data
              end
            when :tund
              # 取ctl，没有则取写缓存，也没有则去掉写兴趣
              ctl = info[ :ctls ].shift

              if ctl
                pack = [ [ 0 ].pack( 'N' ), ctl ].join
                sock.sendmsg( pack, 0, info[ :tun_addr ] )
                next
              end

              data, from = get_buff( info )

              if data.empty?
                mon.remove_interest( :w )
                next
              end

              len = data[ 0, 2 ].unpack( 'n' ).first
              pack = data[ 2, ( 8 + len ) ]
              send_pack( sock, info, pack )

              data = data[ ( 10 + len )..-1 ]

              if from == :cache
                info[ :cache ] = data
              elsif from == :wbuff
                info[ :wbuff ] = data
              end
            end
          end
        end
      end
    rescue Interrupt => e
      puts e.class
      quit!
    end

    def quit!
      pack = [ 0, 7 ].pack( 'NC' )

      @roomd_info[ :clients ].each do | _, client_info |
        tund, _ = client_info

        unless tund.closed?
          tund_info = @infos[ tund ]
          tund.sendmsg( pack, 0, tund_info[ :tun_addr ] )
        end
      end

      exit
    end

    private

    def expire_clients
      Thread.new do
        loop do
          now = Time.new

          @mutex.synchronize do
            @roomd_info[ :clients ].select{ | _, client_info | now - client_info[ 1 ] > 7200 }.each do | sockaddr, client_info |
              close_sock( client_info[ 0 ] )
              @roomd_info[ :clients ].delete( sockaddr )
            end
          end

          sleep 3600
        end
      end
    end

    def loop_resend
      Thread.new do
        loop do
          now = Time.new
          idle = true

          @mutex.synchronize do
            @roomd_info[ :clients ].each do | _, client_info |
              tund, _ = client_info
              tund_info = @infos[ tund ]
              memory = tund_info[ :memories ].first

              if memory
                pack_id, mem = memory
                pack, mem_at, times = mem

                # 超过一秒
                if now - mem_at > 1
                  tund_info[ :memories ].delete( pack_id )

                  # 重传次数超过上限强行关闭dest
                  if times > RESEND_LIMIT
                    dest_id = pack_id[ 4, 4 ]
                    dest, _ = tund_info[ :dests ][ dest_id ]

                    if dest && !dest.closed?
                      puts 'resend too many times'
                      dest.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
                      close_dest( dest, 2 )
                    end

                    next
                  end

                  send_pack( tund, tund_info, pack, times + 1 )

                  # 有搁置的写前文件缓存，加写兴趣
                  if ( tund_info[ :memories ].size < MEMORIES_LIMIT ) && tund_info[ :chunks ].any?
                    tund_info[ :mon ].add_interest( :w )
                  end

                  idle = false
                end
              end
            end
          end

          if idle
            sleep 0.01
          end
        end
      end
    end

    def send_pack( tund, tund_info, pack, tcur = 0 )
      # 发包
      tund.sendmsg( pack, 0, tund_info[ :tun_addr ] )

      # 记写后缓存
      pack_id = pack[ 0, 8 ]
      tund_info[ :memories ][ pack_id ] = [ pack, Time.new, tcur ]

      # 如果是最后一段流量，重发结束包
      err = tund_info[ :dest_fins ][ pack_id ]

      if err
        ctl_pack = [ [ 0, 5, err ].pack( 'NCC' ), pack_id ].join
        tund.sendmsg( ctl_pack, 0, tund_info[ :tun_addr ] )
      end
    end

    def add_ctl( info, ctl )
      info[ :ctls ] << ctl
      info[ :mon ].add_interest( :w )
    end

    def add_buff( info, data )
      info[ :wbuff ] << data

      if info[ :wbuff ].size >= CHUNK_SIZE
        filename = [ info[ :filename ], info[ :chunk_seed ] ].join( '.' )
        chunk_path = File.join( info[ :chunk_dir ], filename )
        IO.binwrite( chunk_path, info[ :wbuff ] )
        info[ :chunks ] << filename
        info[ :chunk_seed ] += 1
        info[ :wbuff ].clear
      end

      info[ :mon ].add_interest( :w )
    end

    def get_buff( info )
      # 先取cache
      # cache为空，取一个chunk放进cache
      # chunks也为空，取wbuff
      data, from = info[ :cache ], :cache

      if data.empty?
        if info[ :chunks ].any?
          # tun写后超过1w，限制内存，暂不读入写前文件
          if ( info[ :role ] == :tund ) && ( info[ :memories ].size > MEMORIES_LIMIT )
            puts 'memories over 1w'
            return [ data, from ]
          end

          path = File.join( info[ :chunk_dir ], info[ :chunks ].shift )
          data = info[ :cache ] = IO.binread( path )

          begin
            File.delete( path )
          rescue Errno::ENOENT
          end
        else
          data, from = info[ :wbuff ], :wbuff
        end
      end

      [ data, from ]
    end

    def close_dest( sock, err = nil )
      puts "close dest by #{ err }"
      info = close_sock( sock )

      if err && info && !info[ :tund ].closed?
        last_pack_id = [ [ info[ :pcur ] ].pack( 'N' ), info[ :id ] ].join
        tund_info = @infos[ info[ :tund ] ]
        _, source_id = tund_info[ :dests ].delete( info[ :id ] )
        tund_info[ :pairs ].delete( source_id )
        tund_info[ :dest_fins ][ last_pack_id ] = err

        ctl = [ [ 5, err ].pack( 'CC' ), last_pack_id ].join
        add_ctl( tund_info, ctl )
      end
    end

    def close_sock( sock )
      sock.close
      @selector.deregister( sock )
      info = @infos.delete( sock )

      if info
        info[ :chunks ].each do | filename |
          begin
            File.delete( File.join( info[ :chunk_dir ], filename ) )
          rescue Errno::ENOENT
          end
        end
      end

      info
    end
  end
end
