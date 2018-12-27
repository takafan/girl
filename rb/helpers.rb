def check_lock
  halt errmsg '已被锁定，不能修改' if File.exist?( '/boot/lock' )
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
