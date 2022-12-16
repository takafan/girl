require 'girl/custom'
require 'girl/head'
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
        girl_port = conf[ :girl_port ]
        ims = conf[ :ims ]
      end

      unless proxyd_port then
        proxyd_port = 6060
      end

      unless girl_port then
        girl_port = 8080
      end

      text = IO.read( '/etc/resolv.conf' )
      match_data = /^nameserver .*\n/.match( text )
      nameserver = match_data ? match_data.to_a.first.split(' ')[ 1 ].strip : '8.8.8.8'

      unless ims then
        ims = []
      end

      puts "girl proxyd #{ Girl::VERSION }"
      puts "proxyd #{ proxyd_port } #{ girl_port } nameserver #{ nameserver }"
      puts "ims #{ ims.inspect }"

      worker = Girl::ProxydWorker.new( proxyd_port, girl_port, nameserver, ims )

      Signal.trap( :TERM ) do
        puts 'exit'
        worker.quit!
      end

      worker.looping
    end

  end
end
