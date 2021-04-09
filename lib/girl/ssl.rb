require 'etc'
require 'girl/concurrent_hash'
require 'girl/head'
require 'girl/ssl_worker'
require 'girl/version'
require 'json'
require 'openssl'
require 'socket'

##
# Girl::Ssl
#
module Girl
  class Ssl

    def initialize( config_path = nil )
      unless config_path then
        config_path = File.expand_path( '../girl.conf.json', __FILE__ )
      end

      raise "missing config file #{ config_path }" unless File.exist?( config_path )

      conf = JSON.parse( IO.binread( config_path ), symbolize_names: true )
      redir_port = conf[ :ssl_port ]
      worker_count = conf[ :worker_count ]

      unless redir_port then
        redir_port = 1080
      end

      nprocessors = Etc.nprocessors

      if worker_count.nil? || worker_count <= 0 || worker_count > nprocessors then
        worker_count = nprocessors
      end

      len = CONSTS.map{ | name | name.size }.max

      CONSTS.each do | name |
        puts "#{ name.gsub( '_', ' ' ).ljust( len ) } #{ Girl.const_get( name ) }"
      end

      title = "girl ssl #{ Girl::VERSION }"
      puts title
      puts "redir port #{ redir_port } worker count #{ worker_count }"

      $0 = title
      workers = []

      worker_count.times do | i |
        workers << fork do
          $0 = 'girl ssl worker'
          worker = Girl::SslWorker.new( redir_port )

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
