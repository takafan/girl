get '/' do
  content_type 'text/html', charset: 'utf-8'

  send_file File.join( settings.public_folder, 'index.html' )
end
