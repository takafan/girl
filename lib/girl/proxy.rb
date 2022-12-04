require 'girl/custom'
require 'girl/head'
require 'girl/proxy_worker'
require 'girl/version'
require 'ipaddr'
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
# Girl::Proxy - 近端
#
#
module Girl
  class Proxy

    def initialize( config_path = nil )
      unless config_path then
        config_path = File.expand_path( '../girl.conf.json', __FILE__ )
      end

      raise "missing config file #{ config_path }" unless File.exist?( config_path )

      conf = JSON.parse( IO.binread( config_path ), symbolize_names: true )
      redir_port = conf[ :redir_port ]
      proxyd_host = conf[ :proxyd_host ]
      proxyd_port = conf[ :proxyd_port ]
      direct_path = conf[ :direct_path ]
      remote_path = conf[ :remote_path ]
      nameserver = conf[ :nameserver ]
      ports_size = conf[ :ports_size ]
      girl_port = conf[ :girl_port ]
      im = conf[ :im ]

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

      unless nameserver then
        nameserver = '114.114.114.114'
      end

      unless ports_size then
        ports_size = 1
      end

      unless girl_port then
        girl_port = 8080
      end

      unless im then
        im = 'office-pc'
      end

      puts "girl proxy #{ Girl::VERSION }"
      puts "redir #{ redir_port } proxyd #{ proxyd_host } #{ proxyd_port } #{ girl_port } nameserver #{ nameserver } ports size #{ ports_size } im #{ im }"
      puts "#{ direct_path } #{ directs.size } directs"
      puts "#{ remote_path } #{ remotes.size } remotes"

      worker = Girl::ProxyWorker.new( redir_port, proxyd_host, proxyd_port, directs, remotes, nameserver, ports_size, girl_port, im )

      Signal.trap( :TERM ) do
        puts 'exit'
        worker.quit!
      end

      worker.looping
    end

  end
end
