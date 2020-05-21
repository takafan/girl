require 'etc'
require 'girl/head'
require 'girl/proxy_custom'
require 'girl/proxy_worker'
require 'girl/version'
require 'ipaddr'
require 'json'
require 'socket'

##
# Girl::Proxy - 代理服务，近端。
#
# 包结构
# ======
#
# tun-proxyd:
#
# hello
#
# proxyd-tun:
#
# Q>: 0 ctlmsg -> C: 1 tund port -> n: tund port
#
# tun-tund:
#
# Q>: 0 ctlmsg -> C: 2 heartbeat  -> C: random char
#                    3 a new src  -> src_addr -> encoded destination address
#                    4 paired     -> src_addr -> n: dst_port
#                    5 dst status -> n: dst_port -> Q>Q>: biggest_dst_pack_id continue_src_pack_id
#                    6 src status -> src_addr -> Q>Q>: biggest_src_pack_id continue_dst_pack_id
#                    7 miss       -> src_addr/n: dst_port -> Q>Q>: pack_id_begin pack_id_end
#                    8 fin1       -> src_addr/n: dst_port -> Q>Q>: biggest_src_pack_id continue_dst_pack_id / biggest_dst_pack_id continue_src_pack_id
#                    9 not use
#                   10 fin2       -> src_addr/n: dst_port
#                   11 not use
#                   12 tund fin
#                   13 tun fin
#
# Q>: 1+ pack_id -> src_addr/n: dst_port -> traffic
#
# close logic
# ===========
#
# 1-1. after close src -> dst closed ? no -> send fin1
# 1-2. recv fin2 -> del src ext
#
# 2-1. recv traffic/fin1/dst status -> dst closed and all traffic received ? -> close src after write
# 2-2. after close src -> dst closed ? yes -> del src ext -> send fin2
#
module Girl
  class Proxy

    def initialize( config_path = nil )
      unless config_path
        config_path = File.expand_path( '../girl.conf.json', __FILE__ )
      end

      unless File.exist?( config_path )
        raise "missing config file #{ config_path }"
      end

      # {
      #     "proxy_port": 6666,                   // 代理服务，近端（本地）端口
      #     "proxyd_host": "1.2.3.4",             // 代理服务，远端服务器
      #     "proxyd_port": 6060,                  // 代理服务，远端端口
      #     "direct_path": "girl.direct.txt",     // 直连ip段
      #     "remote_path": "girl.remote.txt",     // 交给远端解析的域名列表
      #     "proxy_tmp_dir": "/tmp/girl.proxy",   // 近端缓存根路径
      #     "proxyd_tmp_dir": "/tmp/girl.proxyd", // 远端缓存根路径
      #     "im": "girl",                         // 标识，用来识别近端
      #     "worker_count": 4                     // 子进程数，默认取cpu个数
      # }
      conf = JSON.parse( IO.binread( config_path ), symbolize_names: true )
      proxy_port = conf[ :proxy_port ]
      proxyd_host = conf[ :proxyd_host ]
      proxyd_port = conf[ :proxyd_port ]
      direct_path = conf[ :direct_path ]
      remote_path = conf[ :remote_path ]
      proxy_tmp_dir = conf[ :proxy_tmp_dir ]
      im = conf[ :im ]
      worker_count = conf[ :worker_count ]

      unless proxy_port
        proxy_port = 6666
      end

      unless proxyd_host
        raise "missing proxyd host"
      end

      unless proxyd_port
        proxyd_port = 6060
      end

      directs = []

      if direct_path
        unless File.exist?( direct_path )
          raise "not found direct file #{ direct_path }"
        end

        directs = ( RESERVED_ROUTE.split( "\n" ) + IO.binread( direct_path ).split( "\n" ) ).map { | line | IPAddr.new( line.strip ) }
      end

      remotes = []

      if remote_path
        unless File.exist?( remote_path )
          raise "not found remote file #{ remote_path }"
        end

        remotes = IO.binread( remote_path ).split( "\n" ).map { | line | line.strip }
      end

      unless proxy_tmp_dir
        proxy_tmp_dir = '/tmp/girl.proxy'
      end

      unless File.exist?( proxy_tmp_dir )
        Dir.mkdir( proxy_tmp_dir )
      end

      src_chunk_dir = File.join( proxy_tmp_dir, 'src.chunk' )
      dst_chunk_dir = File.join( proxy_tmp_dir, 'dst.chunk' )
      tun_chunk_dir = File.join( proxy_tmp_dir, 'tun.chunk' )

      unless Dir.exist?( proxy_tmp_dir )
        Dir.mkdir( proxy_tmp_dir )
      end

      unless Dir.exist?( src_chunk_dir )
        Dir.mkdir( src_chunk_dir )
      end

      unless Dir.exist?( dst_chunk_dir )
        Dir.mkdir( dst_chunk_dir )
      end

      unless Dir.exist?( tun_chunk_dir )
        Dir.mkdir( tun_chunk_dir )
      end

      unless im
        im = 'girl'
      end

      nprocessors = Etc.nprocessors

      if worker_count.nil? || worker_count <= 0 || worker_count > nprocessors
        worker_count = nprocessors
      end

      title = "girl proxy #{ Girl::VERSION }"
      puts title
      puts "proxy port #{ proxy_port }"
      puts "proxyd host #{ proxyd_host }"
      puts "proxyd port #{ proxyd_port }"
      puts "#{ direct_path } #{ directs.size } directs"
      puts "#{ remote_path } #{ remotes.size } remotes"
      puts "src chunk dir #{ src_chunk_dir }"
      puts "dst chunk dir #{ dst_chunk_dir }"
      puts "tun chunk dir #{ tun_chunk_dir }"
      puts "im #{ im }"
      puts "worker count #{ worker_count }"

      $0 = title
      workers = []

      worker_count.times do | i |
        workers << fork do
          $0 = 'girl proxy worker'
          worker = Girl::ProxyWorker.new( proxy_port, proxyd_host, proxyd_port, directs, remotes, src_chunk_dir, dst_chunk_dir, tun_chunk_dir, im )

          Signal.trap( :TERM ) do
            puts "w#{ i } exit"
            worker.quit!
          end

          worker.looping
        end
      end

      Signal.trap( :TERM ) do
        puts 'trap TERM'
        workers.each do | pid |
          begin
            Process.kill( :TERM, pid )
          rescue Errno::ESRCH => e
            puts e.class
          end
        end
      end

      Process.waitall
    end

  end
end
