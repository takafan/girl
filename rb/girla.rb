require 'json'
require 'sinatra'

set :public_folder, '/srv/girl/dist'
set :server, 'webrick'

SERVICES = %w[ dhcpcd dnsmasq hostapd proxy ]

CUSTOM_SERVICES = %w[ hostapd proxy ]

CONFIG_DIR = '/boot'

CONFIG_FILES = %w[
  dnsmasq.d/wlan0.conf
  dhcpcd.conf
  girl.conf.json
  girl.direct.txt
  girl.remote.txt
  hostapd.conf
]

require File.expand_path( '../helpers.rb', __FILE__ )

Dir[ File.expand_path( '../api/*.rb', __FILE__ ) ].each{ | file | require file }

Signal.trap( :TERM ) do
  puts 'trap TERM'
  Sinatra::Application.quit!
end
