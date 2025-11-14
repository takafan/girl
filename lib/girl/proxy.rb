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

    def initialize(config_path = nil)
      config_path = File.expand_path('../girl.conf.json', __FILE__) unless config_path
      raise "missing config file #{config_path}" unless File.exist?(config_path)

      conf = JSON.parse(IO.binread(config_path), symbolize_names: true)
      puts "load #{config_path} #{conf.inspect}"
      redir_host = conf[:redir_host]
      redir_port = conf[:redir_port]
      memd_port = conf[:memd_port]
      tspd_host = conf[:tspd_host]
      tspd_port = conf[:tspd_port]
      proxyd_host = conf[:proxyd_host]
      proxyd_port = conf[:proxyd_port]
      bigd_port = conf[:bigd_port]
      nameserver = conf[:nameserver]
      im = conf[:im]
      direct_path = conf[:direct_path]
      remote_path = conf[:remote_path]
      appd_host = conf[:appd_host]
      appd_port = conf[:appd_port]
      head_len = conf[:head_len]                       # 头长度
      h_a_new_source = conf[:h_a_new_source]           # A
      h_a_new_p2 = conf[:h_a_new_p2]                   # B
      h_dst_close = conf[:h_dst_close]                 # D
      h_heartbeat = conf[:h_heartbeat]                 # H
      h_p1_close = conf[:h_p1_close]                   # I
      h_p2_close = conf[:h_p2_close]                   # J
      h_p2_traffic = conf[:h_p2_traffic]               # K
      h_query = conf[:h_query]                         # Q
      h_response = conf[:h_response]                   # R
      h_src_close = conf[:h_src_close]                 # S
      h_traffic = conf[:h_traffic]                     # T
      h_dst_switch_to_big = conf[:h_dst_switch_to_big] # U
      h_p2_switch_to_big = conf[:h_p2_switch_to_big]   # V
      h_src_switch_to_big = conf[:h_src_switch_to_big] # W
      h_p1_switch_to_big = conf[:h_p1_switch_to_big]   # X
      expire_connecting = conf[:expire_connecting]     # 连接多久没有建成关闭（秒）
      expire_long_after = conf[:expire_long_after]     # 长连接多久没有新流量关闭（秒）
      expire_proxy_after = conf[:expire_proxy_after]   # proxy多久没有收到流量重建（秒）
      expire_resolv_cache = conf[:expire_resolv_cache] # dns查询结果缓存多久（秒）
      expire_short_after = conf[:expire_short_after]   # 短连接创建多久后关闭（秒）
      is_debug = conf[:is_debug]

      redir_host = redir_host ? redir_host.to_s : '0.0.0.0'
      redir_port = redir_port ? redir_port.to_i : 6666
      memd_port = memd_port ? memd_port.to_i : redir_port + 2
      tspd_host = tspd_host ? tspd_host.to_s : '0.0.0.0'
      tspd_port = tspd_port ? tspd_port.to_i : 7777
      raise "missing proxyd host" unless proxyd_host
      proxyd_port = proxyd_port ? proxyd_port.to_i : 6060
      bigd_port = bigd_port ? bigd_port.to_i : proxyd_port + 1
      nameserver = '114.114.114.114' unless nameserver
      nameservers = nameserver.split(' ')
      im = 'office-pc' unless im
      directs = []

      if direct_path
        raise "not found direct file #{direct_path}" unless File.exist?(direct_path)
        directs = (RESERVED_ROUTE.split("\n") + IO.binread(direct_path).split("\n")).map{|line| IPAddr.new(line.strip)}
      end

      remotes = []

      if remote_path
        raise "not found remote file #{remote_path}" unless File.exist?(remote_path)
        remotes = IO.binread(remote_path).split("\n").map{|line| line.strip}
      end

      appd_host = appd_host ? appd_host.to_s : '127.0.0.1'
      appd_port = appd_port ? appd_port.to_i : 22
      head_len = head_len ? head_len.to_i : 59
      h_a_new_source = h_a_new_source ? h_a_new_source.to_s : 'A'
      h_a_new_p2 = h_a_new_p2 ? h_a_new_p2.to_s : 'B'
      h_dst_close = h_dst_close ? h_dst_close.to_s : 'D'
      h_heartbeat = h_heartbeat ? h_heartbeat.to_s : 'H'
      h_p1_close = h_p1_close ? h_p1_close.to_s : 'I'
      h_p2_close = h_p2_close ? h_p2_close.to_s : 'J'
      h_p2_traffic = h_p2_traffic ? h_p2_traffic.to_s : 'K'
      h_query = h_query ? h_query.to_s : 'Q'
      h_response = h_response ? h_response.to_s : 'R'
      h_src_close = h_src_close ? h_src_close.to_s : 'S'
      h_traffic = h_traffic ? h_traffic.to_s : 'T'
      h_dst_switch_to_big = h_dst_switch_to_big ? h_dst_switch_to_big.to_s : 'U'
      h_p2_switch_to_big = h_p2_switch_to_big ? h_p2_switch_to_big.to_s : 'V'
      h_src_switch_to_big = h_src_switch_to_big ? h_src_switch_to_big.to_s : 'W'
      h_p1_switch_to_big = h_p1_switch_to_big ? h_p1_switch_to_big.to_s : 'X'
      expire_connecting = expire_connecting ? expire_connecting.to_i : 5
      expire_long_after = expire_long_after ? expire_long_after.to_i : 3600
      expire_proxy_after = expire_proxy_after ? expire_proxy_after.to_i : 60
      expire_resolv_cache = expire_resolv_cache ? expire_resolv_cache.to_i : 600
      expire_short_after = expire_short_after ? expire_short_after.to_i : 5
      is_client_fastopen = is_server_fastopen = false

      if RUBY_PLATFORM.include?('linux')
        IO.popen('sysctl -n net.ipv4.tcp_fastopen') do |io|
          output = io.read
          val = output.to_i % 4
          is_client_fastopen = true if [1, 3].include?(val)
          is_server_fastopen = true if [2, 3].include?(val)
        end
      end

      puts "girl proxy #{Girl::VERSION} #{im} #{redir_port} #{tspd_port}"
      puts "#{proxyd_host} #{proxyd_port} #{appd_host} #{appd_port} #{nameservers.inspect} #{is_client_fastopen} #{is_server_fastopen}"
      puts "#{direct_path} #{directs.size} directs"
      puts "#{remote_path} #{remotes.size} remotes"

      if %w[darwin linux].any?{|plat| RUBY_PLATFORM.include?(plat)}
        Process.setrlimit(:NOFILE, RLIMIT)
        puts "NOFILE #{Process.getrlimit(:NOFILE).inspect}"
      end

      worker = Girl::ProxyWorker.new(
        redir_host,
        redir_port,
        memd_port,
        tspd_host,
        tspd_port,
        proxyd_host,
        proxyd_port,
        bigd_port,
        nameservers,
        im,
        directs,
        remotes,
        appd_host,
        appd_port,
        head_len,
        h_a_new_source,
        h_a_new_p2,
        h_dst_close,
        h_heartbeat,
        h_p1_close,
        h_p2_close,
        h_p2_traffic,
        h_query,
        h_response,
        h_src_close,
        h_traffic,
        h_dst_switch_to_big,
        h_p2_switch_to_big,
        h_src_switch_to_big,
        h_p1_switch_to_big,
        expire_connecting,
        expire_long_after,
        expire_proxy_after,
        expire_resolv_cache,
        expire_short_after,
        is_debug,
        is_client_fastopen,
        is_server_fastopen)

      Signal.trap(:TERM) do
        puts 'exit'
        worker.quit!
      end

      worker.looping
    end

  end
end
