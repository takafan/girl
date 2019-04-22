require 'girl/hex'
require 'nio'
require 'socket'

##
# Girl::Tun
#
# tcp流量正常的到达目的地。
#
# usage:
#
# 1. Girl::Tund.new( 9090 ).looping # @server
#
# 2. Girl::Tun.new( '{ your.server.ip }', 9090, 1919 ).looping # @home
#
# 3. dig +short www.google.com @127.0.0.1 -p1717 # dig with girl/resolv, got 216.58.217.196
#
# 4. iptables -t nat -A OUTPUT -p tcp -d 216.58.217.196 -j REDIRECT --to-ports 1919
#
# 5. curl https://www.google.com/
#
# 走向：
#
# tun > roomd
# source > tun > tund > dest
# dest > tund > tun > source
#
# 流量打包成udp，在tun-tund之间传输，包结构：
#
# N: 1+ pcur    -> nn: source_id/dest_id   -> traffic
#    0  ctl msg -> C: 1 heartbeat
#                     2 a new source       -> nn: source_id -> nnN: dst_family dst_port dst_ip
#                     3 paired             -> nn: source_id -> nn: dest_id
#                     4 confirm a pack     -> Nnn: pack_id
#                     5 dest fin           -> C: :eof/:rst -> Nnn: last_pack_id
#                     6 source fin         -> C: :eof/:rst -> Nnn: last_pack_id
#                     7 confirm dest fin   -> nn: dest_id
#                     8 confirm source fin -> nn: source_id
#                     9 tund fin
#                     10 tun fin
#
# infos，存取sock信息，根据角色，sock => {}：
#
# {
#   role: :tun,
#   mon: mon,
#   wbuff: '',
#   cache: '',
#   filename: '',
#   chunk_dir: '',
#   chunks: [],
#   chunk_seed: 0,
#   memories: { pack_id => [ '', now, 0 ] },
#   ctls: [],
#   ctl2_mems: {},
#   ctl6_mems: {},
#   tund_addr: tund_addr,
#   sources: { source_id => [ source, dest_id ] },
#   pairs: { dest_id => source }
# }
#
# {
#   role: :source,
#   mon: mon,
#   wbuff: '',
#   cache: '',
#   filename: '',
#   chunk_dir: '',
#   chunks: [],
#   chunk_seed: 0,
#   id: '',
#   pcur: 0,
#   dest_pcur: 0,
#   pieces: { 2 => '', 4 => '' },
#   dest_fin: [ 1, 1024 ]
# }
#
# role            角色，:redir / :source / :tun
# mon             NIO::Monitor
# wbuff           写前缓存
# cache           块缓存
# filename        [ Process.pid, sock.object_id ].join( '-' )
# chunk_dir       块目录
# chunks          块文件名，wbuff每超过1.4M落一个块
# chunk_seed      块序号
# memories        写后缓存
# ctls            ctl写前缓存。写的时候，先取ctl，ctls为空，取cache，cache为空，取一个chunk放进cache，chunks为空，取wbuff。
# ctl2_mems       ctl2写后缓存
# ctl6_mems       ctl6写后缓存
# tund_addr       另一头地址
# sources         根据source_id，取source和dest_id
# pairs           根据dest_id，取source
# id              [ Process.pid, source.object_id ].pack( 'nn' )
# pcur            打包光标
# dest_pcur       写前光标
# pieces          跳号缓存
# dest_fin        远端传来“dest已关闭”，记在source身上，传完所有流量后关闭source。
#
module Girl
  PACK_SIZE = 1456 # 1492(PPPoE MTU) - 20(IPv4 head) - 8(UDP head) - 8(pack id) = 1456
  CHUNK_SIZE = PACK_SIZE * 1000
  MEMORIES_LIMIT = 10_000 # 写后缓存上限
  RESEND_LIMIT = 20 # 重传次数上限

  class Tun
    def initialize( tund_ip, roomd_port = 9090, redir_port = 1919, source_chunk_dir = '/tmp', tun_chunk_dir = '/tmp', hex_block = nil )
      if hex_block
        Girl::Hex.class_eval( hex_block )
      end

      selector = NIO::Selector.new
      redir = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      redir.bind( Socket.pack_sockaddr_in( redir_port, '0.0.0.0' ) )
      redir.listen( 511 )
      redir_info = {
        role: :redir,
        mon: selector.register( redir, :r )
      }

      @tund_ip = tund_ip
      @roomd_addr = Socket.sockaddr_in( roomd_port, tund_ip )
      @source_chunk_dir = source_chunk_dir
      @tun_chunk_dir = tun_chunk_dir
      @hex = Girl::Hex.new
      @mutex = Mutex.new
      @selector = selector
      @infos = {
        redir => redir_info
      }
      @deregs = []

      apply_tunnel
    end

    def looping
      puts 'looping'

      # 心跳
      loop_heartbeat

      # 释放sock已关闭的monitor
      loop_cleanup

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
            when :redir
              begin
                source, addrinfo = sock.accept_nonblock
              rescue IO::WaitReadable, Errno::EINTR => e
                puts "accept source #{ e.class }"
                next
              end

              begin
                # /usr/include/linux/netfilter_ipv4.h
                option = source.getsockopt( Socket::SOL_IP, 80 )
              rescue Exception => e
                puts "get SO_ORIGINAL_DST #{ e.class }"
                source.close
                next
              end

              source.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )
              source_id = [ Process.pid, source.object_id ].pack( 'nn' )

              @infos[ source ] = {
                role: :source,
                mon: @selector.register( source, :r ),
                wbuff: '',
                cache: '',
                filename: [ Process.pid, source.object_id ].join( '-' ),
                chunk_dir: @source_chunk_dir,
                chunks: [],
                chunk_seed: 0,
                id: source_id,
                pcur: 0,
                dest_pcur: 0,
                pieces: {},
                dest_fin: nil
              }

              @tun_info[ :sources ][ source_id ] = [ source, nil ]
              add_ctl( 2, [ source_id, option.data ].join )
            when :source
              begin
                data = sock.read_nonblock( PACK_SIZE )
              rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
                next
              rescue Exception => e
                err = e.is_a?( EOFError ) ? 1 : 2
                close_source( sock, err )
                next
              end

              pcur = info[ :pcur ] + 1

              # ssh的第一段流量是明文版本号，https的第一段流量含明文域名，所以，混淆第一段流量。
              # 覆盖encode方法自定义混淆。
              if pcur == 1
                data = @hex.encode( data )
              end

              data = [ [ data.bytesize, pcur ].pack( 'nN' ), info[ :id ], data ].join
              add_buff( @tun_info, data )
              info[ :pcur ] = pcur
            when :tun
              data, addrinfo, rflags, *controls = sock.recvmsg
              dest_pcur = data[ 0, 4 ].unpack( 'N' ).first

              if dest_pcur == 0
                ctl_num = data[ 4 ].unpack( 'C' ).first

                case ctl_num
                when 3
                  # 3 paired -> nn: source_id -> nn: dest_id
                  source_id = data[ 5, 4 ]
                  dest_id = data[ 9, 4 ]

                  info[ :ctl2_mems ].delete( source_id )
                  source_pair = info[ :sources ][ source_id ]

                  if source_pair && source_pair[ 1 ].nil?
                    source = source_pair[ 0 ]
                    info[ :pairs ][ dest_id ] = source
                    source_pair[ 1 ] = dest_id
                  end
                when 4
                  # 4 confirm a pack -> Nnn: pack_id
                  pack_id = data[ 5, 8 ]
                  memory = info[ :memories ].delete( pack_id )
                when 5
                  # 5 dest fin -> C: :eof/:rst -> Nnn: last_pack_id
                  err = data[ 5 ].unpack( 'C' ).first
                  last_pack_id = data[ 6, 8 ]
                  last_dest_pcur = last_pack_id[ 0, 4 ].unpack( 'N' ).first
                  dest_id = last_pack_id[ 4, 4 ]
                  add_ctl( 7, dest_id )

                  source = info[ :pairs ][ dest_id ]

                  if source.nil? || source.closed?
                    next
                  end

                  source_info = @infos[ source ]
                  source_info[ :dest_fin ] = [ err, last_dest_pcur ]
                  source_info[ :mon ].add_interest( :w )
                when 8
                  # 8 confirm source fin
                  source_id = data[ 5, 4 ]
                  info[ :ctl6_mems ].delete( source_id )
                when 9
                  # 9 tund fin
                  close_sock( sock )
                  sleep 5
                  apply_tunnel
                end

                next
              end

              pack_id = data[ 0, 8 ]
              add_ctl( 4, pack_id )

              dest_id = pack_id[ 4, 4 ]
              source = info[ :pairs ][ dest_id ]

              if source.nil? || source.closed?
                next
              end

              source_info = @infos[ source ]

              if dest_pcur <= source_info[ :dest_pcur ]
                next
              end

              data = data[ 8..-1 ]

              # 解混淆
              if dest_pcur == 1
                data = @hex.decode( data )
              end

              # 放进source的写前缓存，跳号放碎片缓存
              if dest_pcur - source_info[ :dest_pcur ] == 1
                while source_info[ :pieces ].include?( dest_pcur + 1 )
                  data << source_info[ :pieces ].delete( dest_pcur + 1 )
                  dest_pcur += 1
                end

                add_buff( source_info, data )
                source_info[ :dest_pcur ] = dest_pcur
              else
                source_info[ :pieces ][ dest_pcur ] = data
              end
            end
          end

          if mon.writable?
            case info[ :role ]
            when :source
              data, from = get_buff( info )

              if data.empty?
                # 有关闭标记，且流量已收全，关闭source
                if info[ :dest_fin ]
                  err, last_dest_pcur = info[ :dest_fin ]

                  if last_dest_pcur == info[ :dest_pcur ]
                    if err == 2
                      sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
                    end

                    close_source( sock )
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
                close_source( sock, err )
                next
              end

              data = data[ written..-1 ]

              if from == :cache
                info[ :cache ] = data
              elsif from == :wbuff
                info[ :wbuff ] = data
              end
            when :tun
              # 取ctl，没有则取写缓存，也没有则去掉写兴趣
              ctl = info[ :ctls ].shift

              if ctl
                ctl_num, ctl_data = ctl
                pack = [ [ 0, ctl_num ].pack( 'NC' ), ctl_data ].join
                sock.sendmsg( pack, 0, info[ :tund_addr ] )

                # 其中ctl2（来了一个新source）和ctl6（关闭了一个source）记写后缓存
                if [ 2, 6 ].include?( ctl_num )
                  if ctl_num == 2
                    ctl_sym = :ctl2_mems
                    source_id = ctl_data[ 0, 4 ]
                  elsif ctl_num == 6
                    ctl_sym = :ctl6_mems
                    source_id = ctl_data[ 5, 4 ]
                  end

                  info[ ctl_sym ][ source_id ] = [ pack, Time.new, 0 ]
                end

                next
              end

              data, from = get_buff( info )

              if data.empty?
                mon.remove_interest( :w )
                next
              end

              len = data[ 0, 2 ].unpack( 'n' ).first
              pack = data[ 2, ( 8 + len ) ]
              send_pack( pack )

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
      pack = [ 0, 10 ].pack( 'NC' )
      @tun.sendmsg( pack, 0, @tun_info[ :tund_addr ] )
      exit
    end

    private

    def apply_tunnel
      tun = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      tun.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )
      tun.sendmsg( @hex.hello, 0, @roomd_addr )
      rs, ws = IO.select( [ tun ], [], [], 30 )

      unless rs
        raise 'apply for a tunnel timeout'
      end

      data, addrinfo, rflags, *controls = rs.first.recvmsg
      tund_port = data.unpack( 'n' ).first
      puts "tund #{ tund_port }"

      tun_info = {
        role: :tun,
        mon: @selector.register( tun, :r ),
        wbuff: '',
        cache: '',
        filename: [ Process.pid, tun.object_id ].join( '-' ),
        chunk_dir: @tun_chunk_dir,
        chunks: [],
        chunk_seed: 0,
        memories: {},
        ctls: [],
        ctl2_mems: {},
        ctl6_mems: {},
        tund_addr: Socket.sockaddr_in( tund_port, @tund_ip ),
        sources: {},
        pairs: {}
      }

      @tun = tun
      @tun_info = tun_info
      @infos[ tun ] = tun_info
    end

    def loop_heartbeat
      Thread.new do
        loop do
          pack = [ 0, 1, rand( 128 ) ].pack( 'NCC' )
          @tun.sendmsg( pack, 0, @tun_info[ :tund_addr ] )
          sleep 59
        end
      end
    end

    def loop_cleanup
      Thread.new do
        loop do
          unless @deregs.empty?
            @deregs.each do | sock |
              @selector.deregister( sock )
            end

            @deregs.clear
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
            # 重传ctls
            [ :ctl2_mems, :ctl6_mems ].each do | ctl_sym |
              ctl_mem = @tun_info[ ctl_sym ].first

              if ctl_mem
                source_id, mem = ctl_mem
                pack, mem_at, times = mem

                if now - mem_at > 1
                  @tun_info[ ctl_sym ].delete( source_id )
                  idle = false

                  if times > RESEND_LIMIT
                    source, _ = @tun_info[ :sources ][ source_id ]

                    if source && !source.closed?
                      puts "#{ ctl_sym } too many times"
                      source.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
                      close_source( source, 2 )
                    end

                    next
                  end

                  puts "resend #{ ctl_sym }"
                  @tun.sendmsg( pack, 0, @tun_info[ :tund_addr ] )
                  @tun_info[ ctl_sym ][ source_id ] = [ pack, Time.new, times + 1 ]
                end
              end
            end

            # 重传流量
            memory = @tun_info[ :memories ].first

            if memory
              pack_id, mem = memory
              pack, mem_at, times = mem

              if now - mem_at > 1
                @tun_info[ :memories ].delete( pack_id )
                idle = false

                if times > RESEND_LIMIT
                  source_id = pack_id[ 4, 4 ]
                  source, _ = @tun_info[ :sources ][ source_id ]

                  if source && !source.closed?
                    puts 'resend too many times'
                    source.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
                    close_source( source, 2 )
                  end

                  next
                end

                send_pack( pack, times + 1 )

                # 有搁置的写前块，加写兴趣
                if ( @tun_info[ :memories ].size < MEMORIES_LIMIT ) && @tun_info[ :chunks ].any?
                  @tun_info[ :mon ].add_interest( :w )
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

    def send_pack( pack, tcur = 0 )
      # 发包
      @tun.sendmsg( pack, 0, @tun_info[ :tund_addr ] )

      # 记写后缓存
      pack_id = pack[ 0, 8 ]
      @tun_info[ :memories ][ pack_id ] = [ pack, Time.new, tcur ]
    end

    def add_ctl( ctl_num, ctl_data )
      @tun_info[ :ctls ] << [ ctl_num, ctl_data ]
      @tun_info[ :mon ].add_interest( :w )
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

    # 取写前缓存：
    # 1. 先取cache
    # 2. cache为空，取一个chunk放进cache
    # 3. chunks也为空，取wbuff
    def get_buff( info )
      data, from = info[ :cache ], :cache

      if data.empty?
        if info[ :chunks ].any?
          # tun写后超过1w，限制内存，暂不读入写前文件
          if ( info[ :role ] == :tun ) && ( info[ :memories ].size > MEMORIES_LIMIT )
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

    def close_source( sock, err = nil )
      info = close_sock( sock )
      _, dest_id = @tun_info[ :sources ].delete( info[ :id ] )
      @tun_info[ :pairs ].delete( dest_id )

      if err && info
        last_pack_id = [ [ info[ :pcur ] ].pack( 'N' ), info[ :id ] ].join
        add_ctl( 6, [ [ err ].pack( 'C' ), last_pack_id ].join )
      end
    end

    def close_sock( sock )
      sock.close
      @deregs << sock
      info = @infos.delete( sock )

      if info
        info[ :mon ].remove_interest( :rw )
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
