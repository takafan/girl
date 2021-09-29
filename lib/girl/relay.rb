require 'girl/head'
require 'girl/proxy_custom'
require 'girl/relay_worker'
require 'girl/version'
require 'ipaddr'
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

      im = "#{ im }-relay"

      puts "girl relay #{ Girl::VERSION }"
      puts "resolv #{ resolv_port } nameserver #{ nameserver } resolvd #{ resolvd_port } redir #{ redir_port } proxyd #{ proxyd_host } #{ proxyd_port } im #{ im }"
      puts "#{ direct_path } #{ directs.size } directs"
      puts "#{ remote_path } #{ remotes.size } remotes"

      worker = Girl::RelayWorker.new( resolv_port, nameserver, resolvd_port, redir_port, proxyd_host, proxyd_port, directs, remotes, im )

      Signal.trap( :TERM ) do
        puts 'exit'
        worker.quit!
      end

      worker.looping
    end

  end
end
