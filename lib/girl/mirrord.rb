require 'girl/head'
require 'girl/mirrord_worker'
require 'girl/version'
require 'json'
require 'socket'

##
# Girl::Mirrord - 镜子 服务端
#
module Girl
  class Mirrord

    def initialize( config_path = nil )
      unless config_path then
        config_path = File.expand_path( '../girl.conf.json', __FILE__ )
      end

      raise "missing config file #{ config_path }" unless File.exist?( config_path )

      conf = JSON.parse( IO.binread( config_path ), symbolize_names: true )
      mirrord_port = conf[ :mirrord_port ]
      p2d_host = conf[ :p2d_host ]
      im_infos = conf[ :im_infos ]

      unless mirrord_port then
        mirrord_port = 7070
      end

      unless p2d_host then
        p2d_host = '127.0.0.1'
      end

      raise 'missing im infos' if im_infos.nil? || im_infos.empty?

      puts "girl mirrord #{ Girl::VERSION }"
      puts "mirrord #{ mirrord_port } p2d host #{ p2d_host }"
      puts "im infos #{ im_infos.inspect }"

      if %w[ darwin linux ].any?{ | plat | RUBY_PLATFORM.include?( plat ) } then
        Process.setrlimit( :NOFILE, RLIMIT )
        puts "NOFILE #{ Process.getrlimit( :NOFILE ).inspect }" 
      end

      worker = Girl::MirrordWorker.new( mirrord_port, p2d_host, im_infos )

      Signal.trap( :TERM ) do
        puts 'exit'
        worker.quit!
      end

      worker.looping
    end

  end
end
