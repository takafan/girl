get '/chnroute.txt' do
  check_lock
  
  content_type 'text/plain', charset: 'utf-8'

  send_file '/boot/chnroute.txt'
end
