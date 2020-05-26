get '/girl.direct.txt' do
  check_lock

  content_type 'text/plain', charset: 'utf-8'

  send_file File.join( CONFIG_DIR, 'girl.direct.txt' )
end
