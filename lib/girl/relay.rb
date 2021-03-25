require 'etc'
require 'girl/concurrent_hash'
require 'girl/head'
require 'girl/proxy_custom'
require 'girl/relay_worker'
require 'girl/resolv_custom'
require 'girl/version'
require 'json'
require 'socket'

##
# Girl::Relay
#
module Girl
  class Relay

    def initialize( config_path = nil )
      unless config_path then
        config_path = File.expand_path( '../girl.conf.json', __FILE__ )
      end

      raise "missing config file #{ config_path }" unless File.exist?( config_path )

      conf = JSON.parse( IO.binread( config_path ), symbolize_names: true )
      resolv_port = conf[ :resolv_port ]
      nameserver = conf[ :nameserver ]
      resolvd_port = conf[ :resolvd_port ]
      redir_port = conf[ :relay_port ]
      proxyd_host = conf[ :proxyd_host ]
      proxyd_port = conf[ :proxyd_port ]
      direct_path = conf[ :direct_path ]
      remote_path = conf[ :remote_path ]
      im = conf[ :im ]
      worker_count = conf[ :worker_count ]

      unless resolv_port then
        resolv_port = 1053
      end

      unless nameserver then
        nameserver = '114.114.114.114'
      end

      unless resolvd_port then
        resolvd_port = 5353
      end

      unless redir_port then
        redir_port = 1066
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

      title = "girl relay #{ Girl::VERSION }"
      puts title
      puts "resolv port #{ resolv_port }"
      puts "nameserver #{ nameserver }"
      puts "resolvd port #{ resolvd_port }"
      puts "redir port #{ redir_port }"
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

      $0 = title
      workers = []

      worker_count.times do | i |
        workers << fork do
          $0 = 'girl relay worker'
          worker = Girl::RelayWorker.new( resolv_port, nameserver, resolvd_port, redir_port, proxyd_host, proxyd_port, directs, remotes, im )

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
