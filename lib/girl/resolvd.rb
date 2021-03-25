require 'etc'
require 'json'
require 'socket'
require 'girl/concurrent_hash'
require 'girl/head'
require 'girl/resolv_custom'
require 'girl/resolvd_worker'
require 'girl/version'

##
# Girl::Resolvd
#
module Girl
  class Resolvd

    def initialize( config_path = nil )
      unless config_path then
        config_path = File.expand_path( '../girl.conf.json', __FILE__ )
      end

      raise "missing config file #{ config_path }" unless File.exist?( config_path )

      conf = JSON.parse( IO.binread( config_path ), symbolize_names: true )
      resolvd_port = conf[ :resolvd_port ]
      worker_count = conf[ :worker_count ]

      unless resolvd_port then
        resolvd_port = 5353
      end

      text = IO.read( '/etc/resolv.conf' )
      match_data = /^nameserver .*\n/.match( text )
      nameserver = match_data ? match_data.to_a.first.split(' ')[ 1 ].strip : '8.8.8.8'
      nprocessors = Etc.nprocessors

      if worker_count.nil? || worker_count <= 0 || worker_count > nprocessors then
        worker_count = nprocessors
      end

      title = "girl resolvd #{ Girl::VERSION }"
      puts title
      puts "resolvd port #{ resolvd_port }"
      puts "nameserver #{ nameserver }"
      puts "worker count #{ worker_count }"

      len = CONSTS.map{ | name | name.size }.max

      CONSTS.each do | name |
        puts "#{ name.gsub( '_', ' ' ).ljust( len ) } #{ Girl.const_get( name ) }"
      end

      $0 = title
      workers = []

      worker_count.times do | i |
        workers << fork do
          $0 = 'girl resolvd worker'
          worker = Girl::ResolvdWorker.new( resolvd_port, nameserver )

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
