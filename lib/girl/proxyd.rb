require 'girl/custom'
require 'girl/dns'
require 'girl/head'
require 'girl/proxyd_worker'
require 'girl/version'
require 'json'
require 'socket'

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
        reset_traff_day = conf[ :reset_traff_day ]
      end

      unless proxyd_port then
        proxyd_port = 6060
      end

      unless girl_port then
        girl_port = 8080
      end

      text = IO.read( '/etc/resolv.conf' )
      nameservers = []

      text.split( "\n" ).each do | line |
        match_data = /^nameserver \d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}/.match( line )

        if match_data then
          nameservers << match_data[ 0 ].split(' ')[ 1 ].strip
          break if nameservers.size >= 3
        end
      end

      if nameservers.empty? then
        nameservers << '8.8.8.8'
      end

      if reset_traff_day then
        reset_traff_day = reset_traff_day.to_i
      else
        reset_traff_day = 1
      end

      unless ims then
        ims = []
      end

      puts "girl proxyd #{ Girl::VERSION }"
      puts "proxyd #{ proxyd_port } #{ girl_port } nameservers #{ nameservers.inspect } reset traff day #{ reset_traff_day }"
      puts "ims #{ ims.inspect }"

      if %w[ darwin linux ].any?{ | plat | RUBY_PLATFORM.include?( plat ) } then
        Process.setrlimit( :NOFILE, 1024 )
        puts "NOFILE #{ Process.getrlimit( :NOFILE ).inspect }" 
      end

      worker = Girl::ProxydWorker.new( proxyd_port, girl_port, nameservers, reset_traff_day, ims )

      Signal.trap( :TERM ) do
        puts 'exit'
        worker.quit!
      end

      worker.looping
    end

  end
end
