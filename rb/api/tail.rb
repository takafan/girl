get '/api/tail' do
  check_lock

  service = params[ :service ]

  halt errmsg 'unknown service' unless %w[ dhcpcd dnsmasq hostapd p2p1_sshd redir resolv ].include?( service )

  content_type 'text/plain', charset: 'utf-8'

  output = ''

  IO.popen( "journalctl -u #{ service } -en 1000 --no-pager" ) do | io |
    output = io.read
  end

  output
end
