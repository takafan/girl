post '/api/save_text' do
  check_lock

  data = JSON.parse( request.body.read, symbolize_names: true )

  file = data[ :file ]
  halt errmsg 'unknown file' unless CONFIG_FILES.include?( file )

  text = data[ :text ]
  halt errmsg 'missing text' unless text

  File.open( File.join( CONFIG_DIR, file ), 'w' ) do |f|
    f.puts text
  end

  servs = case file
  when 'dnsmasq.d/wlan0.conf'
    'dnsmasq'
  when 'dhcpcd.conf'
    'dhcpcd'
  when 'girl.conf.json'
    'proxy'
  when 'girl.direct.txt'
    'proxy'
  when 'girl.remote.txt'
    'proxy'
  when 'hostapd.conf'
    'hostapd'
  end

  if servs
    system "systemctl restart #{ servs }"
  end

  success
end
