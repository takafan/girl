require 'etc'
require 'girl/head'
require 'girl/proxyd_custom'
require 'girl/proxyd_worker'
require 'girl/version'
require 'json'
require 'socket'

##
# Girl::Proxyd - 代理服务，远端。
#
# close logic
# ===========
#
# 1-1. after close dst -> src closed ? no -> send fin1
# 1-2. recv fin2 -> del dst ext
#
# 2-1. recv traffic/fin1/src status -> src closed and all traffic received ? -> close dst after write
# 2-2. after close dst -> src closed ? yes -> del dst ext -> send fin2
#
module Girl
  class Proxyd

    def initialize( config_path = nil )
      if config_path
        unless File.exist?( config_path )
          raise "not found config file #{ config_path }"
        end

        conf = JSON.parse( IO.binread( config_path ), symbolize_names: true )
        proxyd_port = conf[ :proxyd_port ]
        proxyd_tmp_dir = conf[ :proxyd_tmp_dir ]
        worker_count = conf[ :worker_count ]
      end

      unless proxyd_port
        proxyd_port = 6060
      end

      unless proxyd_tmp_dir
        proxyd_tmp_dir = '/tmp/girl.proxyd'
      end

      unless File.exist?( proxyd_tmp_dir )
        Dir.mkdir( proxyd_tmp_dir )
      end

      dst_chunk_dir = File.join( proxyd_tmp_dir, 'dst.chunk' )
      tund_chunk_dir = File.join( proxyd_tmp_dir, 'tund.chunk' )

      unless Dir.exist?( proxyd_tmp_dir )
        Dir.mkdir( proxyd_tmp_dir )
      end

      unless Dir.exist?( dst_chunk_dir )
        Dir.mkdir( dst_chunk_dir )
      end

      unless Dir.exist?( tund_chunk_dir )
        Dir.mkdir( tund_chunk_dir )
      end

      nprocessors = Etc.nprocessors

      if worker_count.nil? || worker_count <= 0 || worker_count > nprocessors
        worker_count = nprocessors
      end

      title = "girl proxyd #{ Girl::VERSION }"
      puts title
      puts "proxyd port #{ proxyd_port }"
      puts "dst chunk dir #{ dst_chunk_dir }"
      puts "tund chunk dir #{ tund_chunk_dir }"
      puts "worker count #{ worker_count }"

      $0 = title
      workers = []

      worker_count.times do | i |
        workers << fork do
          $0 = 'girl proxyd worker'
          worker = Girl::ProxydWorker.new( proxyd_port, dst_chunk_dir, tund_chunk_dir )

          Signal.trap( :TERM ) do
            puts "w#{ i } exit"
            worker.quit!
          end

          worker.looping
        end
      end

      Signal.trap( :TERM ) do
        puts 'trap TERM'
        workers.each do | pid |
          begin
            Process.kill( :TERM, pid )
          rescue Errno::ESRCH => e
            puts e.class
          end
        end
      end

      Process.waitall
    end

  end
end
