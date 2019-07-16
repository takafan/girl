require 'json'
require 'sinatra'

set :public_folder, '/srv/girl/dist'
set :server, 'webrick'

module Api
end

module Consts
end

module Helpers
end

API_TEMP = <<EOF
include Consts

def self.registered(app)
  app.helpers Helpers

  __apis__
end
EOF

def inject
  Consts.module_eval( IO.read( File.expand_path( '../consts.rb', __FILE__ ) ) )
  Helpers.module_eval( IO.read( File.expand_path( '../helpers.rb', __FILE__ ) ) )

  apis = Dir[ File.expand_path( '../api/*.rb', __FILE__ ) ].map{ | file | "app.#{ IO.read( file ).strip }" }
  Api.module_eval( API_TEMP.sub( '__apis__', apis.join( "\n" ) ) )
  register Api
end

inject

Signal.trap( :TERM ) do
  puts 'trap TERM'
  Sinatra::Application.quit!
end

Signal.trap( :USR2 ) do
  puts 'trap USR2'
  Sinatra::Application.reset!
  inject
end
