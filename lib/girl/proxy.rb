require 'etc'
require 'girl/head'
require 'girl/proxy_custom'
require 'girl/proxy_worker'
require 'girl/version'
require 'ipaddr'
require 'json'
require 'socket'

=begin
# Girl::Proxy - 代理服务，近端。

## 重传逻辑

1. 每隔一秒询问对面是否空闲
2. 重传队列都为空，返回空闲
3. 对面空闲，遍历dst/src，有跳号包，发miss。没跳号包，距上一次收到新流量不超过5秒，发continue。
4. 收到single miss，添加至resend_singles
5. 收到range miss，添加至resend_ranges
6. 收到continue，删写后，把剩余的写后添加至resend_newers队列
7. 依次重传resend_newers，resend_singles，resend_ranges

## 包结构

tun-proxyd:

hello

proxyd-tun:

Q>: 0 ctlmsg -> C: 1 tund port -> n: tund port

tun-tund:

Q>: 0 ctlmsg -> C: 2 heartbeat         -> not use
                   3 a new source      -> Q>: src id -> encoded destination address
                   4 paired            -> Q>: src id -> n: dst id
                   5 dest status       -> not use
                   6 source status     -> not use
                   7 miss              -> not use
                   8 fin1              -> Q>/n: src/dst id -> Q>: biggest src/dst pack id
                   9 confirm fin1      -> not use
                  10 fin2              -> Q>/n: src/dst id
                  11 confirm fin2      -> not use
                  12 tund fin
                  13 tun fin
                  14 tun ip changed
                  15 single miss       -> Q>/n: src/dst id -> Q>: miss pack id -> Q>*: 至多160个 miss pack id
                  16 range miss        -> Q>/n: src/dst id -> Q>: begin miss pack id -> Q>: end miss pack id -> Q>*: 至多80个miss段
                  17 continue          -> Q>/n: src/dst id -> Q>: continue recv pack id
                  18 is resend ready
                  19 resend ready

Q>: 1+ pack_id -> Q>/n: src/dst id -> traffic

## 近端关闭逻辑

1. 读src -> 读到error -> 关src读 -> rbuff空？ -> src.dst？ -> 关dst写 -> src已双向关？ -> 删src.info
                                                                    -> dst已双向关且src.wbuff空？ -> 删dst.info
                                             -> src.dst_id？ -> 发fin1

2. 写src -> 写光src.wbuff -> src.dst？ -> dst已关读？ -> 关src写 -> src已双向关且src.rbuff空？ -> 删src.info
                          -> src.dst_id？ -> 已连续写入至dst最终包id？ -> 关src写 -> 发fin2 -> src.dst_fin2？ -> 删src.ext

3. 读dst -> 读到error -> 关dst读 -> dst.src.wbuff空？ -> 关src写 -> dst已双向关？ -> 删dst.info
                                                                -> src已双向关？ -> 删src.info

4. 写dst -> 转光dst.src.rbuff -> src已关读？ -> 关dst写 -> dst已双向关且src.wbuff空？ -> 删dst.info

5. 读tun -> 读到fin1，得到对面dst最终包id -> 已连续写入至dst最终包id？ -> 关src写 -> 发fin2 -> src.dst_fin2？ -> 删src.ext
         -> 读到fin2，对面已结束写 -> src.dst_fin2置true -> src已双向关？ -> 删src.ext

6. 写tun -> 转光src.rbuff -> src已关读？ -> 发fin1

7. 主动关src -> src.dst？ -> dst没关？ -> 主动关dst
             -> src.dst_id？ -> 发fin1和fin2

8. 主动关dst -> dst.src没关？ -> 主动关src

9. 主动关tun -> tun.srcs.each没关？-> 主动关src

## 远端关闭逻辑

1. 读dst -> 读到error -> 关dst读 -> rbuff空？-> 发fin1

2. 写dst -> 写光dst.wbuff -> 已连续写入至src最终包id？ -> 关dst写 -> 发fin2 -> dst.src_fin2？ -> 删dst.ext

3. 读tund -> 读到fin1，得到对面src最终包id -> 已连续写入至src最终包id？ -> 关dst写 -> 发fin2 -> dst.src_fin2？ -> 删dst.ext
         -> 读到fin2，对面已结束写 -> dst.src_fin2置true -> dst已双向关？ -> 删dst.ext

4. 写tund -> 转光dst.rbuff -> dst已关读？ -> 发fin1

5. 主动关dst -> 发fin1和fin2

6. 主动关tund -> tund.dsts.each没关？-> 主动关dst
=end

module Girl
  class Proxy

    def initialize( config_path = nil )
      unless config_path then
        config_path = File.expand_path( '../girl.conf.json', __FILE__ )
      end

      unless File.exist?( config_path ) then
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

      unless proxy_port then
        proxy_port = 6666
      end

      unless proxyd_host then
        raise "missing proxyd host"
      end

      unless proxyd_port then
        proxyd_port = 6060
      end

      directs = []

      if direct_path then
        unless File.exist?( direct_path ) then
          raise "not found direct file #{ direct_path }"
        end

        directs = ( RESERVED_ROUTE.split( "\n" ) + IO.binread( direct_path ).split( "\n" ) ).map { | line | IPAddr.new( line.strip ) }
      end

      remotes = []

      if remote_path then
        unless File.exist?( remote_path ) then
          raise "not found remote file #{ remote_path }"
        end

        remotes = IO.binread( remote_path ).split( "\n" ).map { | line | line.strip }
      end

      unless im then
        im = 'girl'
      end

      nprocessors = Etc.nprocessors

      if worker_count.nil? || worker_count <= 0 || worker_count > nprocessors then
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

      len = CONSTS.map{ | name | name.size }.max

      CONSTS.each do | name |
        puts "#{ name.gsub( '_', ' ' ).ljust( len ) } #{ Girl.const_get( name ) }"
      end

      if RUBY_PLATFORM.include?( 'linux' ) then
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
