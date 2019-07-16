def check_lock
  if File.exist?( File.join( CONFIG_DIR, 'lock' ) )
    content_type 'text/plain', charset: 'utf-8'
    halt '已被锁定。'
  end
end

def errmsg( msg = nil, contents = {} )
  JSON.generate({
    success: false,
    msg: msg
  }.merge( contents ))
end

def success( contents = {} )
  JSON.generate({
    success: true
  }.merge( contents ))
end
