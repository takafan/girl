require 'girl/hex'
require 'nio'
require 'socket'

module Girl
  class Tund
    # 1492(PPPoE MTU) - 20(IPv4 head) - 8(UDP head) - 4(id) = 1460
    PACK_SIZE = 1460
    CHUNK_SIZE = PACK_SIZE * 1000

    def initialize( roomd_port = 9090, dest_chunk_dir = '/tmp', tund_chunk_dir = '/tmp', resend_limit = 20 )
      # infos 存取sock信息，根据角色，sock => {}
      #
      # {
      #   id: '',
      #   role: :dest,
      #   mon: mon,
      #   close_by: :source_eof1,
      #   wbuff: '',
      #   cache: '',
      #   chunk_dir: '',
      #   chunks: [],
      #   chunk_seed: 0,
      #   pieces: { 2 => '', 4 => '' },
      #   last_from_source: 1024,
      #   pcur: 0,
      #   tund: tund
      # }
      #
      # {
      #   id: '',
      #   role: :tund,
      #   mon: mon,
      #   close_by: :dest_eof2,
      #   wbuff: '',
      #   cache: '',
      #   chunk_dir: '',
      #   chunks: [],
      #   chunk_seed: 0,
      #   ctl2: '',
      #   mems_size: 0,
      #   resends: [],
      #   rcur: 0,
      #   err_from_dest: 1,
      #   last_from_dest: 1024,
      #   dest: dest,
      #   tun_addr: addrinfo
      # }
      #
      # id               用于文件缓存文件名，跨进程唯一
      # role             角色，:roomd / :dest / :tund
      # mon              NIO::Monitor
      # close_by         关闭标记，流量传完后关闭sock
      # wbuff            写缓存
      # cache            写的时候：先取cache，cache为空，取一个chunk放进cache，chunks也为空，取wbuff。
      # chunk_dir        文件缓存目录
      # chunks           文件缓存
      # chunk_seed       文件自增序号
      # pieces           跳号缓存
      # last_from_source 对面source的最后一个包序号
      # pcur             打包光标，打包dest流量，最后一个进tund写缓存的包号。
      # tund             对应的tund
      # room_addr        ctl1的来源地址
      # ctl2             ctl msg 2
      # mems_size        写后计数
      # resends          重传缓存
      # rcur             读光标，读tun流量，最后一个进dest写缓存的包号。（跳号包放pieces）
      # err_from_dest    1 eof / 2 rst
      # last_from_dest   dest读到异常时的打包光标
      # dest             对应的dest
      # tun_addr         另一头地址
      @infos = {}
      # 写后缓存
      # {
      #   [ sock, pack_id ] => [ '', Time.new, 0 ]
      # }
      @memories = {}
      @mutex = Mutex.new
      @selector = NIO::Selector.new
      @dest_chunk_dir = dest_chunk_dir
      @tund_chunk_dir = tund_chunk_dir
      @resend_limit = resend_limit
      @hex = Girl::Hex.new
      @roomd = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      @roomd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      @roomd.bind( Socket.pack_sockaddr_in( roomd_port, '0.0.0.0' ) )
      puts "roomd listening on #{ roomd_port }"

      roomd_mon = @selector.register( @roomd, :r )
      @infos[ @roomd ] = {
        id: [ Process.pid, @roomd.object_id ].join( '-' ),
        role: :roomd,
        mon: roomd_mon
      }
    end

    def looping
      puts 'looping'

      # 一秒重传
      Thread.new do
        loop do
          memory = @memories.first

          if memory
            now = Time.new
            key, mem = memory
            data, mem_at, times = mem

            if now - mem_at > 1
              sock, pack_id = key

              @mutex.synchronize do
                @memories.delete( key )

                if sock.closed?
                  next
                end

                # 超过重传次数关闭通道
                if times > @resend_limit
                  puts 'resend too many times'
                  close_tund( sock )
                  next
                end

                info = @infos[ sock ]
                pack_id = data[ 0, 4 ].unpack( 'N' ).first

                begin
                  sock.sendmsg( data, 0, info[ :tun_addr ] )
                rescue Errno::ENETUNREACH, IOError => e
                  puts "resend #{ e.class }"
                  close_tund( sock )
                  next
                end

                @memories[ [ sock, pack_id ] ] = [ data, now, times + 1 ]

                # 如果是最后一个包，发送close1
                if info[ :last_from_dest ] && ( pack_id == info[ :last_from_dest ] )
                  pack = [ 0, 5, info[ :err_from_dest ], pack_id ].pack( 'NCCN' )

                  begin
                    sock.sendmsg( pack, 0, info[ :tun_addr ] )
                  rescue Errno::ENETUNREACH, IOError => e
                    puts "resend close1 #{ e.class }"
                    close_tund( sock )
                    next
                  end
                end
              end

              next
            end
          end

          sleep 0.01
        end
      end

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
              # roomd收到申请，创建一个dest与目的地建立连接，创建一个tund等tun连过来
              data, addrinfo, rflags, *controls = sock.recvmsg
              now = Time.new
              puts "#{ addrinfo.ip_unpack.first } #{ now } #{ @infos.size } p#{ Process.pid }"

              unless data[ 0, 5 ].unpack( 'NC' ) == [ 0, 1 ]
                puts "roomd got unknown ctlmsg #{ data.inspect }"
                next
              end

              ret = @hex.decode( data[ 5..-1 ], addrinfo )

              unless ret[ :success ]
                puts ret[ :error ]
                next
              end

              dst_addr = ret[ :dst_addr ]
              dest = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
              dest.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )

              begin
                dest.connect_nonblock( dst_addr )
              rescue IO::WaitWritable, Errno::EINTR
              rescue Exception => e
                puts "connect to destination #{ e.class }"
                dest.close
                next
              end

              tund = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
              tund.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )
              tund_port  = tund.local_address.ip_unpack.last
              ctl2 = [ 2, tund_port ].pack( 'Cn' )

              dest_mon = @selector.register( dest, :r )
              tund_mon = @selector.register( tund, :rw )

              @infos[ dest ] = {
                id: [ Process.pid, dest.object_id ].join( '-' ),
                role: :dest,
                mon: dest_mon,
                close_by: nil,
                wbuff: '',
                cache: '',
                chunk_dir: @dest_chunk_dir,
                chunks: [],
                chunk_seed: 0,
                pieces: {},
                last_from_source: nil,
                pcur: 0,
                tund: tund
              }

              @infos[ tund ] = {
                id: [ Process.pid, tund.object_id ].join( '-' ),
                role: :tund,
                mon: tund_mon,
                close_by: nil,
                wbuff: '',
                cache: '',
                chunk_dir: @tund_chunk_dir,
                chunks: [],
                chunk_seed: 0,
                room_addr: addrinfo,
                ctl2: ctl2,
                mems_size: 0,
                resends: [],
                rcur: 0,
                err_from_dest: nil,
                last_from_dest: nil,
                dest: dest,
                tun_addr: nil
              }
            when :dest
              # 读dest，放进tund的写缓存
              begin
                data = sock.read_nonblock( PACK_SIZE )
              rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
                next
              rescue Exception => e
                close_dest( sock, e )
                next
              end

              pack_id = info[ :pcur ] + 1

              if pack_id == 1
                data = @hex.swap( data )
              end

              # 流量长度，包号，流量
              data = [ [ data.bytesize, pack_id ].pack( 'nN' ), data ].join
              tund_info = @infos[ info[ :tund ] ]

              if tund_info[ :tun_addr ]
                write_buff2( tund_info, data )
              else
                write_buff( tund_info, data )
              end

              info[ :pcur ] = pack_id
            when :tund
              # 读tund，放进dest的写缓存
              data, addrinfo, rflags, *controls = sock.recvmsg

              # 第一段流量进来的时候记对面地址
              unless info[ :tun_addr ]
                info[ :tun_addr ] = addrinfo
                info[ :mon ].add_interest( :w )
              end

              dest_info = @infos[ info[ :dest ] ]
              pack_id = data[ 0, 4 ].unpack( 'N' ).first

              if pack_id == 0
                ctl_num = data[ 4 ].unpack( 'C' ).first

                case ctl_num
                when 4
                  # 4 confirm a pack -> N: pack_id
                  confirm_id = data[ 5, 4 ].unpack( 'N' ).first
                  @memories.delete( [ sock, confirm_id ] )
                  info[ :mems_size ] -= 1
                  info[ :mon ].add_interest( :w )
                when 6
                  # 6 source close2
                  info[ :close_by ] = :source_close2
                  info[ :mon ].add_interest( :w )
                when 7
                  # 7 source close1 -> C: 1 eof / 2 rst -> N: last_pack_id
                  if info[ :dest ].closed?
                    next
                  end

                  errno, last_from_source = data[ 5, 5 ].unpack( 'CN' )
                  close_by = ( errno == 1 ? :source_eof1 : :source_rst1 )
                  dest_info[ :last_from_source ] = last_from_source
                  dest_info[ :close_by ] = close_by
                  dest_info[ :mon ].add_interest( :w )
                end

                next
              end

              ctlmsg = [ 4, pack_id ].pack( 'CN' )
              write_buff2( info, pack_ctlmsg( ctlmsg ) )

              if info[ :dest ].closed?
                next
              end

              if pack_id <= info[ :rcur ]
                next
              end

              data = data[ 4..-1 ]

              if pack_id == 1
                data = @hex.swap( data )
              end

              # 连号放写缓存，跳号放碎片缓存
              if pack_id - info[ :rcur ] == 1
                while dest_info[ :pieces ].include?( pack_id + 1 )
                  data << dest_info[ :pieces ].delete( pack_id + 1 )
                  pack_id += 1
                end

                write_buff2( dest_info, data )
                info[ :rcur ] = pack_id
              else
                dest_info[ :pieces ][ pack_id ] = data
              end
            end
          end

          if mon.writable?
            case info[ :role ]
            when :dest
              data, from = read_buff( info )

              if data.empty?
                tund_info = @infos[ info[ :tund ] ]

                # 有关闭标记，且流量已经收全，关闭dest，给tund打关闭标记，告诉对面结束了
                if info[ :close_by ] && ( info[ :last_from_source ] == tund_info[ :rcur ] )
                  if info[ :close_by ] == :source_rst1
                    sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
                  end

                  close_sock( sock )
                  tund_info[ :close_by ] = :dest_close2
                  ctlmsg = [ 8 ].pack( 'C' )
                  write_buff2( tund_info, pack_ctlmsg( ctlmsg ) )
                  next
                end

                mon.remove_interest( :w )
                next
              end

              begin
                written = sock.write_nonblock( data )
              rescue IO::WaitWritable, Errno::EINTR, IO::WaitReadable => e
                next
              rescue Exception => e
                close_dest( sock, e )
                next
              end

              data = data[ written..-1 ]

              if from == :cache
                info[ :cache ] = data
              elsif from == :wbuff
                info[ :wbuff ] = data
              end
            when :tund
              # tund的第一次写兴趣，roomd返回tund端口号给申请者
              unless info[ :tun_addr ]
                begin
                  @roomd.sendmsg( [ [ 0 ].pack( 'N' ), info[ :ctl2 ] ].join, 0, info[ :room_addr ] )
                rescue Errno::ENETUNREACH, IOError => e
                  puts "send to room #{ e.class }"
                  close_tund( sock )
                  next
                end

                mon.remove_interest( :w )
                next
              end

              # 取写缓存
              data, from = read_buff( info )

              if data.empty?
                if info[ :close_by ]
                  close_sock( sock )
                else
                  mon.remove_interest( :w )
                end

                next
              end

              len, pack_id = data[ 0, 6 ].unpack( 'nN' )
              pack = data[ 2, ( 4 + len ) ]

              begin
                sock.sendmsg( pack, 0, info[ :tun_addr ] )
              rescue Errno::ENETUNREACH, IOError => e
                puts "send to tun #{ e.class }"
                close_tund( sock )
                next
              end

              if pack_id > 0
                @memories[ [ sock, pack_id ] ] = [ pack, Time.new, 0 ]
                info[ :mems_size ] += 1

                # 如果是最后一个包，发送close1
                if info[ :last_from_dest ] && ( pack_id == info[ :last_from_dest ] )
                  ctlmsg = [ 5, info[ :err_from_dest ], pack_id ].pack( 'CCN' )
                  write_buff2( info, pack_ctlmsg( ctlmsg ) )
                end
              end

              data = data[ ( 6 + len )..-1 ]

              if from == :cache
                info[ :cache ] = data
              elsif from == :wbuff
                info[ :wbuff ] = data
              end
            end
          end
        end
      end
    end

    private

    def write_buff( info, data )
      info[ :wbuff ] << data

      if info[ :wbuff ].size >= CHUNK_SIZE
        filename = [ info[ :id ], info[ :chunk_seed ] ].join( '.' )
        chunk_path = File.join( info[ :chunk_dir ], filename )
        IO.binwrite( chunk_path, info[ :wbuff ] )
        info[ :chunks ] << filename
        info[ :chunk_seed ] += 1
        info[ :wbuff ].clear
      end
    end

    def write_buff2( info, data )
      write_buff( info, data )
      info[ :mon ].add_interest( :w )
    end

    def read_buff( info )
      # 先取cache
      # cache为空，取一个chunk放进cache
      # chunks也为空，取wbuff
      data, from = info[ :cache ], :cache

      if data.empty?
        if info[ :chunks ].any?
          # tund写后超过1000，限制内存，暂不读入写前文件
          if info[ :role ] == :tund && info[ :mems_size ] > 1000
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

    def pack_ctlmsg( data )
      # 流量长度，包号，流量
      [ [ data.bytesize, 0 ].pack( 'nN' ), data ].join
    end

    def close_dest( sock, e )
      info = close_sock( sock )
      tund_info = @infos[ info[ :tund ] ]

      if info[ :close_by ]
        ctlmsg = [ 8 ].pack( 'C' )
      else
        err = e.is_a?( EOFError ) ? 1 : 2
        tund_info[ :err_from_dest ] = err
        tund_info[ :last_from_dest ] = info[ :pcur ]
        ctlmsg = [ 5, err, info[ :pcur ] ].pack( 'CCN' )
      end

      write_buff2( tund_info, pack_ctlmsg( ctlmsg ) )
    end

    def close_tund( sock )
      info = close_sock( sock )

      if info && !info[ :dest ].closed?
        info[ :dest ].setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
        close_sock( info[ :dest ] )
      end
    end

    def close_sock( sock )
      sock.close
      @selector.deregister( sock )
      @memories.delete( sock )
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
