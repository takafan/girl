require 'girl/custom'
require 'girl/head'
require 'girl/relay_worker'
require 'girl/version'
require 'json'
require 'socket'

##
# Girl::Relay - 中继
#
module Girl
  class Relay

    def initialize( config_path = nil )
      if config_path then
        raise "not found config file #{ config_path }" unless File.exist?( config_path )
        conf = JSON.parse( IO.binread( config_path ), symbolize_names: true )
        relay_proxyd_port = conf[ :relay_proxyd_port ]
        relay_girl_port = conf[ :relay_girl_port ]
        proxyd_host = conf[ :proxyd_host ]
        proxyd_port = conf[ :proxyd_port ]
        girl_port = conf[ :girl_port ]
      end

      unless relay_proxyd_port then
        relay_proxyd_port = 5060
      end

      unless relay_girl_port then
        relay_girl_port = 5080
      end

      raise "missing proxyd host" unless proxyd_host

      unless proxyd_port then
        proxyd_port = 6060
      end

      unless girl_port then
        girl_port = 8080
      end

      puts "girl relay #{ Girl::VERSION }"
      puts "relay #{ relay_proxyd_port } #{ relay_girl_port } to #{ proxyd_host } #{ proxyd_port } #{ girl_port }"

      if %w[ darwin linux ].any?{ | plat | RUBY_PLATFORM.include?( plat ) } then
        Process.setrlimit( :NOFILE, 1024 )
        puts "NOFILE #{ Process.getrlimit( :NOFILE ).inspect }" 
      end

      worker = Girl::RelayWorker.new( relay_proxyd_port, relay_girl_port, proxyd_host, proxyd_port, girl_port )

      Signal.trap( :TERM ) do
        puts 'exit'
        worker.quit!
      end

      worker.looping
    end

  end
end
