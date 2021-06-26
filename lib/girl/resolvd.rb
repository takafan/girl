require 'json'
require 'socket'
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

      unless resolvd_port then
        resolvd_port = 5353
      end

      text = IO.read( '/etc/resolv.conf' )
      match_data = /^nameserver .*\n/.match( text )
      nameserver = match_data ? match_data.to_a.first.split(' ')[ 1 ].strip : '8.8.8.8'
      len = CONSTS.map{ | name | name.size }.max

      CONSTS.each do | name |
        puts "#{ name.gsub( '_', ' ' ).ljust( len ) } #{ Girl.const_get( name ) }"
      end

      title = "girl resolvd #{ Girl::VERSION }"
      puts title
      puts "resolvd #{ resolvd_port } nameserver #{ nameserver }"

      worker = Girl::ResolvdWorker.new( resolvd_port, nameserver )

      Signal.trap( :TERM ) do
        puts 'exit'
        worker.quit!
      end

      worker.looping
    end

  end
end
