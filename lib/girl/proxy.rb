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
# Q>: 0 ctlmsg -> C: 2 heartbeat     -> C: random char
#                    3 a new source  -> Q>: src id -> encoded destination address
#                    4 paired        -> Q>: src id -> n: dst port
#                    5 dest status   -> n: dst port -> Q>: biggest relayed dst pack id -> Q>: continue src pack id
#                    6 source status -> Q>: src id -> Q>: biggest relayed src pack id -> Q>: continue dst pack id
#                    7 miss          -> Q>/n: src id / dst port -> Q>: pack id begin -> Q>:  pack id end
#                    8 fin1          -> Q>/n: src id / dst port -> Q>: biggest src pack id / biggest dst pack id -> Q>: continue dst pack id / continue src pack id
#                    9 not use
#                   10 fin2          -> Q>/n: src id / dst port
#                   11 not use
#                   12 tund fin
#                   13 tun fin
#                   14 tun ip changed
#                   15 multi miss     -> Q>/n: src id / dst port -> Q>: pack id begin -> Q>: pack id end -> Q>*
#
# Q>: 1+ pack_id -> Q>/n: src id / dst port -> traffic
#
# close logic
# ===========
#
# 1-1. after close src -> dst closed ? no -> send fin1
# 1-2. tun recv fin2 -> del src ext
#
# 2-1. tun recv fin1 -> all traffic received ? -> close src after write
# 2-2. tun recv traffic -> dst closed and all traffic received ? -> close src after write
# 2-3. after close src -> dst closed ? yes -> del src ext -> send fin2
#
# 3-1. after close dst -> src closed ? no -> send fin1
# 3-2. tund recv fin2 -> del dst ext
#
# 4-1. tund recv fin1 -> all traffic received ? -> close dst after write
# 4-2. tund recv traffic -> src closed and all traffic received ? -> close dst after write
# 4-3. after close dst -> src closed ? yes -> del dst ext -> send fin2
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
      #     "im": "girl",                         // 标识，用来识别近端
      #     "worker_count": 4                     // 子进程数，默认取cpu个数
      # }
      conf = JSON.parse( IO.binread( config_path ), symbolize_names: true )
      proxy_port = conf[ :proxy_port ]
      proxyd_host = conf[ :proxyd_host ]
      proxyd_port = conf[ :proxyd_port ]
      direct_path = conf[ :direct_path ]
      remote_path = conf[ :remote_path ]
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
      puts "im #{ im }"
      puts "worker count #{ worker_count }"

      names = %w[
        PACK_SIZE
        READ_SIZE
        WMEMS_LIMIT
        RESUME_BELOW
        EXPIRE_NEW
        EXPIRE_AFTER
        CHECK_EXPIRE_INTERVAL
        CHECK_STATUS_INTERVAL
        SEND_STATUS_UNTIL
        MULTI_MISS_SIZE
        MISS_RANGE_LIMIT
        CONFUSE_UNTIL
        RESOLV_CACHE_EXPIRE
      ]

      len = names.map{ | name | name.size }.max

      names.each do | name |
        puts "#{ name.gsub( '_', ' ' ).ljust( len ) } #{ Girl.const_get( name ) }"
      end

      if RUBY_PLATFORM.include?( 'linux' )
        $0 = title
        workers = []

        worker_count.times do | i |
          workers << fork do
            $0 = 'girl proxy worker'
            worker = Girl::ProxyWorker.new( proxy_port, proxyd_host, proxyd_port, directs, remotes, im )

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
      else
        Girl::ProxyWorker.new( proxy_port, proxyd_host, proxyd_port, directs, remotes, im ).looping
      end
    end

  end
end
