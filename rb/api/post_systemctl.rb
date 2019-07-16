post '/api/systemctl' do
  check_lock

  data = JSON.parse( request.body.read, symbolize_names: true )

  command = data[ :command ]
  service = data[ :service ]

  unless %w[ restart start stop enable disable status ].include?( command )
    halt errmsg 'unknown command'
  end

  case command
  when 'restart', 'status'
    halt errmsg 'unknown service' unless SERVICES.include?( service )
  when 'start', 'stop', 'enable', 'disable'
    halt errmsg 'unknown service' unless CUSTOM_SERVICES.include?( service )
  end

  res = {}

  IO.popen( "systemctl #{ command } #{ service }" ) do | io |
    output = io.read

    if command == 'status'
      res[ :active ] = output[ /Active:.+/ ]
      res[ :loaded ] = output[ /Loaded:.+/ ]
    end
  end

  success( res )
end
