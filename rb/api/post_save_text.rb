post '/api/save_text' do
  check_lock

  data = JSON.parse( request.body.read, symbolize_names: true )

  file = data[ :file ]
  text = data[ :text ]

  unless CONFIG_FILES.include?( file )
    halt errmsg 'unknown file'
  end

  File.open( File.join( CONFIG_DIR, file ), 'w' ) do |f|
    f.puts text
  end

  servs = case file
  when 'dnsmasq.d/wlan0.conf'
    'dnsmasq'
  when 'dhcpcd.conf'
    'dhcpcd'
  when 'girl.custom.txt'
    'resolv tun'
  when 'girl.tund'
    'p1 resolv tun'
  when 'hostapd.conf'
    'hostapd'
  when 'nameservers.txt'
    'resolv'
  end

  if servs
    system "systemctl restart #{ servs }"
  end

  success
end
