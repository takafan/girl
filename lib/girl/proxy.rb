require 'girl/custom'
require 'girl/dns'
require 'girl/head'
require 'girl/proxy_worker'
require 'girl/version'
require 'ipaddr'
require 'json'
require 'socket'

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
      tspd_port = conf[ :tspd_port ]
      proxyd_host = conf[ :proxyd_host ]
      proxyd_port = conf[ :proxyd_port ]
      girl_port = conf[ :girl_port ]
      
      nameserver = conf[ :nameserver ]
      im = conf[ :im ]
      direct_path = conf[ :direct_path ]
      remote_path = conf[ :remote_path ]

      unless redir_port then
        redir_port = 6666
      end

      unless tspd_port then
        tspd_port = 7777
      end

      raise "missing proxyd host" unless proxyd_host

      unless proxyd_port then
        proxyd_port = 6060
      end

      unless girl_port then
        girl_port = 8080
      end

      unless nameserver then
        nameserver = '114.114.114.114'
      end

      nameservers = nameserver.split( ' ' )

      unless im then
        im = 'office-pc'
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

      puts "girl proxy #{ Girl::VERSION }"
      puts "redir #{ redir_port } proxyd #{ proxyd_host } #{ proxyd_port } #{ girl_port } #{ tspd_port } nameservers #{ nameservers.inspect } im #{ im }"
      puts "#{ direct_path } #{ directs.size } directs"
      puts "#{ remote_path } #{ remotes.size } remotes"

      if %w[ darwin linux ].any?{ | plat | RUBY_PLATFORM.include?( plat ) } then
        Process.setrlimit( :NOFILE, RLIMIT )
        puts "NOFILE #{ Process.getrlimit( :NOFILE ).inspect }" 
      end
      
      worker = Girl::ProxyWorker.new( redir_port, proxyd_host, proxyd_port, girl_port, tspd_port, nameservers, im, directs, remotes )

      Signal.trap( :TERM ) do
        puts 'exit'
        worker.quit!
      end

      worker.looping
    end

  end
end
