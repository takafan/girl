require 'json'
require 'sinatra'

set :public_folder, '/srv/girl/dist'
set :server, 'webrick'

SERVICES = %w[ dhcpcd dnsmasq hostapd resolv tun ]

CUSTOM_SERVICES = %w[ hostapd resolv tun ]

CONFIG_DIR = '/boot'

CONFIG_FILES = %w[
  dnsmasq.d/wlan0.conf
  dhcpcd.conf
  girl.custom.txt
  girl.im
  girl.tund
  hostapd.conf
  nameservers.txt
]

require File.expand_path( '../helpers.rb', __FILE__ )

Dir[ File.expand_path( '../api/*.rb', __FILE__ ) ].each{ | file | require file }

Signal.trap( :TERM ) do
  puts 'trap TERM'
  Sinatra::Application.quit!
end
