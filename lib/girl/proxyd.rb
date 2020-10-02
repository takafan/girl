require 'etc'
require 'girl/head'
require 'girl/proxyd_custom'
require 'girl/proxyd_worker'
require 'girl/version'
require 'json'
require 'socket'

##
# Girl::Proxyd - 代理服务，远端。
#
module Girl
  class Proxyd

    def initialize( config_path = nil )
      if config_path then
        unless File.exist?( config_path ) then
          raise "not found config file #{ config_path }"
        end

        conf = JSON.parse( IO.binread( config_path ), symbolize_names: true )
        proxyd_port = conf[ :proxyd_port ]
        worker_count = conf[ :worker_count ]
      end

      unless proxyd_port then
        proxyd_port = 6060
      end

      nprocessors = Etc.nprocessors

      if worker_count.nil? || worker_count <= 0 || worker_count > nprocessors then
        worker_count = nprocessors
      end

      title = "girl proxyd #{ Girl::VERSION }"
      puts title
      puts "proxyd port #{ proxyd_port }"
      puts "worker count #{ worker_count }"

      names = %w[
        PACK_SIZE
        READ_SIZE
        WAFTERS_LIMIT
        RESUME_BELOW
        SEND_HELLO_COUNT
        EXPIRE_AFTER
        CHECK_EXPIRE_INTERVAL
        CHECK_STATUS_INTERVAL
        SEND_MISS_AFTER
        MISS_SINGLE_LIMIT
        MISS_RANGE_LIMIT
        CONFUSE_UNTIL
        RESOLV_CACHE_EXPIRE
      ]

      len = names.map{ | name | name.size }.max

      names.each do | name |
        puts "#{ name.gsub( '_', ' ' ).ljust( len ) } #{ Girl.const_get( name ) }"
      end

      $0 = title
      workers = []

      worker_count.times do | i |
        workers << fork do
          $0 = 'girl proxyd worker'
          worker = Girl::ProxydWorker.new( proxyd_port )

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
