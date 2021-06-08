require 'etc'
require 'girl/head'
require 'girl/proxyd_custom'
require 'girl/proxyd_worker'
require 'girl/version'
require 'json'
require 'net/dns'
require 'socket'

unless Net::DNS::RR.const_defined?(:DNAME) then
  module Net
    module DNS
      class RR
        class DNAME < RR
        end
      end
    end
  end
end

##
# Girl::Proxyd - 远端
#
module Girl
  class Proxyd

    def initialize( config_path = nil )
      if config_path then
        raise "not found config file #{ config_path }" unless File.exist?( config_path )
        conf = JSON.parse( IO.binread( config_path ), symbolize_names: true )
        proxyd_port = conf[ :proxyd_port ]
        infod_port = conf[ :infod_port ]
        worker_count = conf[ :worker_count ]
      end

      unless proxyd_port then
        proxyd_port = 6060
      end

      unless infod_port then
        infod_port = 6070
      end

      text = IO.read( '/etc/resolv.conf' )
      match_data = /^nameserver .*\n/.match( text )
      nameserver = match_data ? match_data.to_a.first.split(' ')[ 1 ].strip : '8.8.8.8'
      nprocessors = Etc.nprocessors

      if worker_count.nil? || worker_count <= 0 || worker_count > nprocessors then
        worker_count = nprocessors
      end

      len = CONSTS.map{ | name | name.size }.max

      CONSTS.each do | name |
        puts "#{ name.gsub( '_', ' ' ).ljust( len ) } #{ Girl.const_get( name ) }"
      end

      title = "girl proxyd #{ Girl::VERSION }"
      puts title
      puts "proxyd port #{ proxyd_port } infod port #{ infod_port } nameserver #{ nameserver } worker count #{ worker_count }"

      $0 = title
      workers = []

      worker_count.times do | i |
        workers << fork do
          $0 = 'girl proxyd worker'
          worker = Girl::ProxydWorker.new( proxyd_port, infod_port, nameserver )

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
