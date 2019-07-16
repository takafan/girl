get '/api/tail/:service' do
  check_lock

  service = params[ :service ]

  halt errmsg 'unknown service' unless SERVICES.include?( service )

  content_type 'text/plain', charset: 'utf-8'

  output = ''

  IO.popen( "journalctl -u #{ service } -en 1000 --no-pager" ) do | io |
    output = io.read
  end

  output
end
