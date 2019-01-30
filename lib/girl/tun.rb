require 'girl/hex'
require 'nio'
require 'socket'

##
# 走向：
#
# source > tun > tund > dest
# dest > tund > tun > source
#
# 流量打包成udp，包结构：
#
# N: 1+ pack id -> traffic
#    0  ctl msg -> C: 1 apply for a tunnel -> nnN: dst_family dst_port dst_ip
#                     2 tund port -> n: port
#                     3 hello
#                     4 confirm a pack -> N: pack_id
#                     5 dest close1 -> C: 1 eof / 2 rst -> N: last_pack_id
#                     6 source close2
#                     7 source close1 -> C: 1 eof / 2 rst -> N: last_pack_id
#                     8 dest close2
#
# 重发：
#
# 一秒未收到确认，重发。
#
# 关闭事件：
#
# dest exception
# > close dest, buff [ 5.. ] on tund
# > [ 5.. ] arrived at tun, set :dest_eof1/:dest_rst1 on source
# > all packs written to source
# > set SO_LINGER 1, 0 if :dest_rst1
# > close source, set :source_close2 and buff [ 6 ] on tun
# > close tun
# > [ 6 ] arrived at tund, set :source_close2 on tund
# > close tund
#
# source exception
# > close source, buff [ 7.. ] on tun
# > [ 7.. ] arrived at tund, set :source_eof1/:source_rst1 on dest
# > all packs written to dest
# > set SO_LINGER 1, 0 if :source_rst1
# > close dest, set :dest_close2 and buff [ 8 ] on tund
# > close tund
# > [ 8 ] arrived at tun, set :dest_close2 on tun
# > close tun
#
# 特殊情况：
#
# 1. tun收到[ 5.. ]，但source已关闭，忽略。
# 2. source收到关闭事件时，已经被打了:dest_eof1，改打:source_close2在tun上，传[ 6 ]。
# 3. tund收到[ 7.. ]，但dest已关闭，忽略。
# 4. dest收到关闭事件时，已经被打了:source_eof1，改打:dest_close2在tund上，传[ 8 ]。
#
module Girl
  class Tun
    # 1492(PPPoE MTU) - 20(IPv4 head) - 8(UDP head) - 4(id) = 1460
    PACK_SIZE = 1460
    CHUNK_SIZE = PACK_SIZE * 1000

    def initialize( roomd_ip, roomd_port = 9090, redir_port = 1919, resend_port = 1920, source_chunk_dir = '/tmp', tun_chunk_dir = '/tmp', resend_times = 20, hex_block = nil)
      if hex_block
        Girl::Hex.class_eval( hex_block )
      end

      # infos，存取sock信息，根据角色，sock => {}：
      #
      # {
      #   id: '',
      #   role: :source,
      #   mon: mon,
      #   close_by: :dest_eof1,
      #   wbuff: '',
      #   cache: '',
      #   chunk_dir: '',
      #   chunks: [],
      #   chunk_seed: 0,
      #   pieces: { 2 => '', 4 => '' },
      #   last_from_dest: 1024,
      #   pcur: 0,
      #   tun: tun
      # }
      #
      # {
      #   id: '',
      #   role: :tun,
      #   mon: mon,
      #   close_by: :source_eof2,
      #   wbuff: '',
      #   cache: '',
      #   chunk_dir: '',
      #   chunks: [],
      #   chunk_seed: 0,
      #   ctl1: '',
      #   rcur: 0,
      #   wmems: { 2 => [ '', now, 0 ], 3 => [ '', now, 0 ], 7 => [ '', now, 0 ] },
      #   err_from_source: 1,
      #   last_from_source: 1024,
      #   source: source,
      #   tund_addr: addrinfo
      # }
      #
      # id:               用于文件缓存文件名，跨进程唯一
      # role:             角色，:redir / :resend / :source / :tun
      # mon:              NIO::Monitor
      # close_by:         关闭标记，流量传完后关闭sock
      # wbuff:            写缓存
      # cache:            写的时候：先取cache，cache为空，取一个chunk放进cache，chunks也为空，取wbuff。
      # chunk_dir:        文件缓存目录
      # chunks:           文件缓存，wbuff每超过1.4M落一个文件，文件名加进chunks。
      # chunk_seed:       文件自增序号
      # pieces:           跳号缓存
      # last_from_dest:   对面dest的最后一个包序号
      # pcur:             打包光标，打包source流量，最后一个进tun写缓存的包号。
      # tun:              对应的tun
      # ctl1:             ctl msg 1
      # rcur:             读光标，读tund流量，最后一个进source写缓存的包号。（跳号包放pieces）
      # wmems:            写后缓存
      # err_from_source:  1 eof / 2 rst
      # last_from_source: source读到异常时的打包光标
      # source:           对应的source
      # tund_addr:        另一头地址
      @infos = {}
      # 写后缓存
      @memories = {}
      @selector = NIO::Selector.new
      @roomd_ip = roomd_ip
      @roomd_addr = Socket.sockaddr_in( roomd_port, roomd_ip )
      @source_chunk_dir = source_chunk_dir
      @tun_chunk_dir = tun_chunk_dir
      @resend_times = resend_times
      @hex = Girl::Hex.new
      redir = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
      redir.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      redir.bind( Socket.pack_sockaddr_in( redir_port, '0.0.0.0' ) )
      redir.listen( 511 )
      puts "redir listening on #{ redir_port } roomd #{ roomd_ip } #{ roomd_port }"

      resend = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
      resend.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
      resend.bind( Socket.sockaddr_in( resend_port, '127.0.0.1' ) )
      puts "resend listening on #{ resend_port }"

      redir_mon = @selector.register( redir, :r )
      @infos[ redir ] = {
        id: [ Process.pid, redir.object_id ].join( '-' ),
        role: :redir,
        mon: redir_mon
      }

      resend_mon = @selector.register( resend, :r )
      @infos[ resend ] = {
        id: [ Process.pid, resend.object_id ].join( '-' ),
        role: :resend,
        mon: resend_mon
      }
    end

    def looping
      puts 'looping'

      loop do
        @selector.select do | mon |
          sock = mon.io

          if sock.closed?
            puts 'sock already closed'

            if mon.readable?
              puts 'skip read'
            end

            if mon.writable?
              puts 'skip write'
            end

            next
          end

          info = @infos[ sock ]

          if mon.readable?
            case info[ :role ]
            when :redir
              # 接受一个source，创建一个对应的tun
              begin
                source, addrinfo = sock.accept_nonblock
              rescue IO::WaitReadable, Errno::EINTR => e
                puts "accept source #{ e.class }"
                next
              end

              now = Time.new
              puts "#{ addrinfo.ip_unpack.first } #{ now } p#{ Process.pid }"
              source.setsockopt( Socket::SOL_TCP, Socket::TCP_NODELAY, 1 )

              begin
                # /usr/include/linux/netfilter_ipv4.h
                option = source.getsockopt( Socket::SOL_IP, 80 )
              rescue Exception => e
                puts "get SO_ORIGINAL_DST #{ e.class }"
                source.close
                next
              end

              ctl1 = "#{ [ 1 ].pack( 'C' ) }#{ @hex.mix( option.data ) }"
              tun = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
              tun.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
              tun.bind( Socket.sockaddr_in( 0, '0.0.0.0' ) )

              source_mon = @selector.register( source, :r )
              tun_mon = @selector.register( tun, :rw )

              @infos[ source ] = {
                id: [ Process.pid, source.object_id ].join( '-' ),
                role: :source,
                mon: source_mon,
                close_by: nil,
                wbuff: '',
                cache: '',
                chunk_dir: @source_chunk_dir,
                chunks: [],
                chunk_seed: 0,
                pieces: {},
                pcur: 0,
                last_from_dest: nil,
                tun: tun
              }

              @infos[ tun ] = {
                id: [ Process.pid, tun.object_id ].join( '-' ),
                role: :tun,
                mon: tun_mon,
                close_by: nil,
                wbuff: '',
                cache: '',
                chunk_dir: @tun_chunk_dir,
                chunks: [],
                chunk_seed: 0,
                ctl1: ctl1,
                rcur: 0,
                err_from_source: nil,
                last_from_source: nil,
                source: source,
                tund_addr: nil
              }

              @memories[ tun ] = {}
            when :resend
              # 重传
              data, addrinfo, rflags, *controls = sock.recvmsg
              now = Time.new

              @memories.each do | tun, mems |
                tun_info = @infos[ tun ]

                # 一秒重传
                mems.select{ | pack_id, mem | now - mem[ 1 ] >= 1 }.each do | pack_id, mem |
                  mem_data, mem_at, times = mem

                  # 重传超过x次关闭通道
                  if times >= @resend_times
                    puts 'resend too many times'
                    close_tun( tun )
                    break
                  end

                  begin
                    tun.sendmsg( mem_data, 0, tun_info[ :tund_addr ] )
                  rescue Errno::ENETUNREACH => e
                    puts "send to tund #{ e.class }"
                    close_tun( tun )
                    break
                  end

                  # 重发close1
                  if tun_info[ :last_from_source ] && ( pack_id == tun_info[ :last_from_source ] )
                    ctlmsg = [ 7, tun_info[ :err_from_source ], pack_id ].pack( 'CCN' )
                    write_buff2( tun_info, pack_ctlmsg( ctlmsg ) )
                  end

                  @memories[ tun ][ pack_id ] = [ mem_data, now, times + 1 ]
                end
              end
            when :source
              # 读source，放进tun的写缓存
              begin
                data = sock.read_nonblock( PACK_SIZE )
              rescue IO::WaitReadable, Errno::EINTR, IO::WaitWritable => e
                next
              rescue Exception => e
                close_source( sock, e )
                next
              end

              pack_id = info[ :pcur ] + 1

              if pack_id == 1
                data = @hex.swap( data )
              end

              data = "#{ [ 4 + data.bytesize ].pack( 'n' ) }#{ [ pack_id ].pack( 'N' ) }#{ data }"
              tun_info = @infos[ info[ :tun ] ]

              if tun_info[ :tund_addr ]
                write_buff2( tun_info, data )
              else
                write_buff( tun_info, data )
              end

              info[ :pcur ] = pack_id
            when :tun
              # 读tun，放进source的写缓存
              data, addrinfo, rflags, *controls = sock.recvmsg
              source_info = @infos[ info[ :source ] ]
              pack_id = data[ 0, 4 ].unpack( 'N' ).first

              if pack_id == 0
                ctl_num = data[ 4 ].unpack( 'C' ).first

                case ctl_num
                when 2
                  # 2 tund port -> n: port
                  tund_port = data[ 5, 2 ].unpack( 'n' ).first
                  tund_addr = Socket.pack_sockaddr_in( tund_port, @roomd_ip )
                  info[ :tund_addr ] = tund_addr

                  # 发hello给tund，source建好连接却不主动上传流量的场合，这个hello替source打洞。
                  ctlmsg = [ 3 ].pack( 'C' )
                  write_buff2( info, pack_ctlmsg( ctlmsg ) )
                when 4
                  # 4 confirm a pack -> N: pack_id
                  confirm_id = data[ 5, 4 ].unpack( 'N' ).first
                  @memories[ sock ].delete( confirm_id )
                  info[ :mon ].add_interest( :w )
                when 5
                  # 5 dest close1 -> C: 1 eof / 2 rst -> N: last_pack_id

                  if info[ :source ].closed?
                    next
                  end

                  errno, last_from_dest = data[ 5, 5 ].unpack( 'CN' )
                  close_by = ( errno == 1 ? :dest_eof1 : :dest_rst1 )
                  source_info[ :close_by ] = close_by
                  source_info[ :last_from_dest ] = last_from_dest
                  source_info[ :mon ].add_interest( :w )
                when 8
                  # 8 dest close2
                  info[ :close_by ] = :dest_close2
                  info[ :mon ].add_interest( :w )
                end

                next
              end

              ctlmsg = [ 4, pack_id ].pack( 'CN' )
              write_buff2( info, pack_ctlmsg( ctlmsg ) )

              if info[ :source ].closed?
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
                while source_info[ :pieces ].include?( pack_id + 1 )
                  data << source_info[ :pieces ].delete( pack_id + 1 )
                  pack_id += 1
                end

                write_buff2( source_info, data )
                info[ :rcur ] = pack_id
              else
                source_info[ :pieces ][ pack_id ] = data
              end
            end
          end

          if mon.writable?
            case info[ :role ]
            when :source
              data = read_buff( info )

              if data.empty?
                tun_info = @infos[ info[ :tun ] ]

                # 有关闭标记，且流量已经收全，关闭source，给tun打关闭标记，告诉对面结束了
                if info[ :close_by ] && ( info[ :last_from_dest ] == tun_info[ :rcur ] )
                  if info[ :close_by ] == :dest_rst1
                    sock.setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
                  end

                  close_sock( sock )
                  tun_info[ :close_by ] = :source_close2
                  ctlmsg = [ 6 ].pack( 'C' )
                  write_buff2( tun_info, pack_ctlmsg( ctlmsg ) )
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
                close_source( sock, e )
                next
              end

              data = data[ written..-1 ]

              if info[ :cache ].empty?
                info[ :wbuff ] = data
              else
                info[ :cache ] = data
              end
            when :tun
              # tun的第一次写兴趣，向roomd申请一个tunnel
              unless info[ :tund_addr ]
                begin
                  sock.sendmsg( "#{ [ 0 ].pack( 'N' ) }#{ info[ :ctl1 ] }", 0, @roomd_addr )
                rescue Errno::ENETUNREACH => e
                  puts "send to roomd #{ e.class }"
                  close_tun( sock )
                  next
                end

                mon.remove_interest( :w )
                next
              end

              # 写后缓存超过1000，停止写
              if @memories[ sock ].size > 1000
                mon.remove_interest( :w )
                next
              end

              # 取写前缓存
              data = read_buff( info )

              if data.empty?
                # 有关闭标记，关闭tun
                if info[ :close_by ]
                  close_sock( sock )
                else
                  mon.remove_interest( :w )
                end

                next
              end

              len, pack_id = data[ 0, 6 ].unpack( 'nN' )
              pack = data[ 2, len ]

              begin
                sock.sendmsg( pack, 0, info[ :tund_addr ] )
              rescue Errno::ENETUNREACH => e
                puts "send to tund #{ e.class }"
                close_tun( sock )
                next
              end

              if pack_id > 0
                @memories[ sock ][ pack_id ] = [ pack, Time.new, 0 ]
              end

              data = data[ ( 2 + len )..-1 ]

              if info[ :cache ].empty?
                info[ :wbuff ] = data
              else
                info[ :cache ] = data
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
      data = info[ :cache ]

      if data.empty?
        if info[ :chunks ].any?
          path = File.join( info[ :chunk_dir ], info[ :chunks ].shift )
          data = info[ :cache ] = IO.binread( path )

          begin
            File.delete( path )
          rescue Errno::ENOENT
          end
        else
          data = info[ :wbuff ]
        end
      end

      return data
    end

    def pack_ctlmsg( data )
      "#{ [ data.bytesize + 4, 0 ].pack( 'nN' ) }#{ data }"
    end

    def close_source( sock, e )
      info = close_sock( sock )
      tun_info = @infos[ info[ :tun ] ]

      if info[ :close_by ]
        ctlmsg = [ 6 ].pack( 'C' )
      else
        err = e.is_a?( EOFError ) ? 1 : 2
        tun_info[ :err_from_source ] = err
        tun_info[ :last_from_source ] = info[ :pcur ]
        ctlmsg = [ 7, err, info[ :pcur ] ].pack( 'CCN' )
      end

      write_buff2( tun_info, pack_ctlmsg( ctlmsg ) )
    end

    def close_tun( sock )
      info = close_sock( sock )

      unless info[ :source ].closed?
        info[ :source ].setsockopt( Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack( 'ii' ) )
        close_sock( info[ :source ] )
      end
    end

    def close_sock( sock )
      sock.close
      @selector.deregister( sock )
      @memories.delete( sock )
      info = @infos.delete( sock )
      info[ :chunks ].each do | filename |
        begin
          File.delete( File.join( info[ :chunk_dir ], filename ) )
        rescue Errno::ENOENT
        end
      end

      return info
    end
  end
end
