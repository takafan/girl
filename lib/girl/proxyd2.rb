require 'girl/dns'
require 'girl/head'
require 'girl/proxyd_worker2'
require 'girl/version'
require 'json'
require 'socket'

##
# Girl::Proxyd2 - 远端
#
module Girl
  class Proxyd2

    def initialize( config_path = nil )
      if config_path then
        raise "not found config file #{ config_path }" unless File.exist?( config_path )
        conf = JSON.parse( IO.binread( config_path ), symbolize_names: true )
        puts "load #{ config_path } #{ conf.inspect }"
        proxyd_port = conf[ :proxyd_port ]
        memd_port = conf[ :memd_port ]
        nameserver = conf[ :nameserver ]
        reset_traff_day = conf[ :reset_traff_day ]
        ims = conf[ :ims ]
        head_len = conf[ :head_len ]             # 头长度
        h_a_new_source = conf[ :h_a_new_source ] # A
        h_dst_close = conf[ :h_dst_close ]       # D
        h_query = conf[ :h_query ]               # Q
        h_response = conf[ :h_response ]         # R
        h_src_close = conf[ :h_src_close ]       # S
        h_traffic = conf[ :h_traffic ]           # T
        expire_connecting = conf[ :expire_connecting ]   # 连接多久没有建成关闭（秒）
        expire_long_after = conf[ :expire_long_after ]   # 长连接多久没有新流量关闭（秒）
        expire_short_after = conf[ :expire_short_after ] # 短连接创建多久后关闭（秒）
        is_debug = conf[ :is_debug ]
      end

      proxyd_port = proxyd_port ? proxyd_port.to_i : 6060
      memd_port = memd_port ? memd_port.to_i : proxyd_port + 1

      if nameserver then
        nameservers = nameserver.split( ' ' )
      else
        nameservers = []
        resolv_path = '/etc/resolv.conf'

        if File.exist?( resolv_path ) then
          text = IO.read( '/etc/resolv.conf' )

          text.split( "\n" ).each do | line |
            match_data = /^nameserver \d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}/.match( line )

            if match_data then
              nameservers << match_data[ 0 ].split(' ')[ 1 ].strip
              break if nameservers.size >= 3
            end
          end
        end
      end

      nameservers << '8.8.8.8' if nameservers.empty?
      reset_traff_day = reset_traff_day ? reset_traff_day.to_i : 1
      ims = [] unless ims
      head_len = head_len ? head_len.to_i : 59
      h_a_new_source = h_a_new_source ? h_a_new_source.to_s : 'A'
      h_dst_close = h_dst_close ? h_dst_close.to_s : 'D'
      h_query = h_query ? h_query.to_s : 'Q'
      h_response = h_response ? h_response.to_s : 'R'
      h_src_close = h_src_close ? h_src_close.to_s : 'S'
      h_traffic = h_traffic ? h_traffic.to_s : 'T'
      expire_connecting = expire_connecting ? expire_connecting.to_i : 5
      expire_long_after = expire_long_after ? expire_long_after.to_i : 3600
      expire_short_after = expire_short_after ? expire_short_after.to_i : 5
      is_server_fastopen = false

      if RUBY_PLATFORM.include?( 'linux' ) then
        IO.popen( 'sysctl -n net.ipv4.tcp_fastopen' ) do | io |
          output = io.read
          val = output.to_i % 4

          if [ 2, 3 ].include?( val ) then
            is_server_fastopen = true
          end
        end
      end

      puts "girl proxyd2 #{ Girl::VERSION }"
      puts "proxyd2 #{ proxyd_port } #{ nameservers.inspect } #{ reset_traff_day } #{ is_server_fastopen }"

      if %w[ darwin linux ].any?{ | plat | RUBY_PLATFORM.include?( plat ) } then
        Process.setrlimit( :NOFILE, RLIMIT )
        puts "NOFILE #{ Process.getrlimit( :NOFILE ).inspect }"
      end

      worker = Girl::ProxydWorker2.new(
        proxyd_port,
        memd_port,
        nameservers,
        reset_traff_day,
        ims,
        head_len,
        h_a_new_source,
        h_dst_close,
        h_query,
        h_response,
        h_src_close,
        h_traffic,
        expire_connecting,
        expire_long_after,
        expire_short_after,
        is_debug,
        is_server_fastopen )

      Signal.trap( :TERM ) do
        puts 'exit'
        worker.quit!
      end

      worker.looping
    end

  end
end
