get '/api/ip' do
  check_lock

  content_type 'text/plain', charset: 'utf-8'

  output = ''

  IO.popen( 'ip a' ) do | io |
    output = io.read
  end

  output
end
