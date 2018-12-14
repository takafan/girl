post '/api/save_text' do
  check_lock

  data = Oj.load( request.body.read )

  file = data[ :file ]
  text = data[ :text ]

  unless CONFIG_FILES.include?( file )
    halt errmsg 'unknown file'
  end

  File.open( File.join( '/boot', file ), 'w' ) do |f|
    f.puts text
  end

  success
end
