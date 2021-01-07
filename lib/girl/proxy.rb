require 'etc'
require 'girl/concurrent_hash'
require 'girl/head'
require 'girl/proxy_custom'
require 'girl/proxy_worker'
require 'girl/version'
require 'ipaddr'
require 'json'
require 'socket'

##
# Girl::Proxy - 近端
#
=begin

# ctlmsg结构

proxy-proxyd:

Q>: 0 ctlmsg -> C: 1 hello -> hello

proxyd-proxy:

Q>: 0 ctlmsg -> C: 1 tund port       -> n: tund port
                   2 heartbeat       NOT USE
                   3 a new source    -> Q>: src id -> encoded destination address
                   4 paired          -> Q>: src id -> n: dst id
                   5 dest status     NOT USE
                   6 source status   NOT USE
                   7 miss            NOT USE
                   8 fin1            NOT USE
                   9 confirm fin1    NOT USE
                  10 fin2            NOT USE
                  11 confirm fin2    NOT USE
                  12 tund fin
                  13 tun fin
                  14 tun ip changed  NOT USE
                  15 single miss     NOT USE
                  16 range miss      NOT USE
                  17 continue        NOT USE
                  18 is resend ready NOT USE
                  19 resend ready    NOT USE

local-infod:

C: 101 traff infos

infod-local:

C: 101 traff infos -> [ C: im len -> im -> Q>: traff in ->  Q>: traff out ]

=end

module Girl
  class Proxy

    def initialize( config_path = nil )
      unless config_path then
        config_path = File.expand_path( '../girl.conf.json', __FILE__ )
      end

      raise "missing config file #{ config_path }" unless File.exist?( config_path )

      # {
      #     "redir_port": 6666,                   // 近端（本地）端口
      #     "proxyd_host": "1.2.3.4",             // 远端服务器
      #     "proxyd_port": 6060,                  // 远端端口
      #     "direct_path": "girl.direct.txt",     // 直连ip段
      #     "remote_path": "girl.remote.txt",     // 交给远端解析的域名列表
      #     "im": "girl",                         // 标识，用来识别近端
      #     "worker_count": 1                     // 子进程数，默认取cpu个数
      # }
      conf = JSON.parse( IO.binread( config_path ), symbolize_names: true )
      redir_port = conf[ :redir_port ]
      proxyd_host = conf[ :proxyd_host ]
      proxyd_port = conf[ :proxyd_port ]
      direct_path = conf[ :direct_path ]
      remote_path = conf[ :remote_path ]
      im = conf[ :im ]
      worker_count = conf[ :worker_count ]

      unless redir_port then
        redir_port = 6666
      end

      raise "missing proxyd host" unless proxyd_host

      unless proxyd_port then
        proxyd_port = 6060
      end

      directs = []

      if direct_path then
        raise "not found direct file #{ direct_path }" unless File.exist?( direct_path )
        directs = ( RESERVED_ROUTE.split( "\n" ) + IO.binread( direct_path ).split( "\n" ) ).map{ | line | IPAddr.new( line.strip ) }
      end

      remotes = []

      if remote_path then
        raise "not found remote file #{ remote_path }" unless File.exist?( remote_path )
        remotes = IO.binread( remote_path ).split( "\n" ).map{ | line | line.strip }
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
      puts "redir port #{ redir_port }"
      puts "proxyd host #{ proxyd_host }"
      puts "proxyd port #{ proxyd_port }"
      puts "#{ direct_path } #{ directs.size } directs"
      puts "#{ remote_path } #{ remotes.size } remotes"
      puts "im #{ im }"
      puts "worker count #{ worker_count }"

      Girl::Custom.constants.each do | name |
        puts "#{ name } #{ Girl::Custom.const_get( name ).inspect }"
      end

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
            worker = Girl::ProxyWorker.new( redir_port, proxyd_host, proxyd_port, directs, remotes, im )

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
        Girl::ProxyWorker.new( redir_port, proxyd_host, proxyd_port, directs, remotes, im ).looping
      end
    end

  end
end
