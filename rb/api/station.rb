get '/api/station' do
  check_lock

  content_type 'text/plain', charset: 'utf-8'

  output = ''

  IO.popen( 'iw dev wlan0 station dump' ) do | io |
    output = io.read
  end

  output
end
