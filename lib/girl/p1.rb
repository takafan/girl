require 'girl/concurrent_hash'
require 'girl/head'
require 'girl/p1_worker'
require 'girl/version'
require 'json'
require 'socket'

##
# Girl::P1 - 镜子 p1端
#
module Girl
  class P1

    def initialize( config_path = nil )
      unless config_path then
        config_path = File.expand_path( '../girl.conf.json', __FILE__ )
      end

      raise "missing config file #{ config_path }" unless File.exist?( config_path )

      conf = JSON.parse( IO.binread( config_path ), symbolize_names: true )
      mirrord_host = conf[ :proxyd_host ]
      mirrord_port = conf[ :mirrord_port ]
      appd_host = conf[ :appd_host ]
      appd_port = conf[ :appd_port ]
      im = conf[ :im ]

      raise 'missing mirrord host' unless mirrord_host

      unless mirrord_port then
        mirrord_port = 7070
      end

      unless appd_host then
        appd_host = '127.0.0.1'
      end

      unless appd_port then
        appd_port = 22
      end

      unless im then
        im = 'office-pi'
      end

      puts "girl p1 #{ Girl::VERSION }"
      puts "mirrord #{ mirrord_host } #{ mirrord_port } appd #{ appd_host } #{ appd_port } im #{ im }"

      worker = Girl::P1Worker.new( mirrord_host, mirrord_port, appd_host, appd_port, im )

      Signal.trap( :TERM ) do
        puts 'exit'
        worker.quit!
      end

      worker.looping
    end

  end
end
