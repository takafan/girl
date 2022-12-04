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
        ports_size = conf[ :ports_size ]
        tund_port = conf[ :tund_port ]
        girl_port = conf[ :girl_port ]
        ims = conf[ :ims ]
      end

      unless proxyd_port then
        proxyd_port = 6060
      end

      unless ports_size then
        ports_size = 1
      end

      unless tund_port then
        tund_port = 0
      end

      unless girl_port then
        girl_port = 8080
      end

      unless ims then
        ims = []
      end

      text = IO.read( '/etc/resolv.conf' )
      match_data = /^nameserver .*\n/.match( text )
      nameserver = match_data ? match_data.to_a.first.split(' ')[ 1 ].strip : '8.8.8.8'

      puts "girl proxyd #{ Girl::VERSION }"
      puts "proxyd #{ proxyd_port } #{ girl_port } nameserver #{ nameserver } ports size #{ ports_size } tund port #{ tund_port }"
      puts "ims #{ ims.inspect }"

      worker = Girl::ProxydWorker.new( proxyd_port, nameserver, ports_size, tund_port, girl_port, ims )

      Signal.trap( :TERM ) do
        puts 'exit'
        worker.quit!
      end

      worker.looping
    end

  end
end
