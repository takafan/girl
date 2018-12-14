def check_lock
  halt errmsg '已被锁定，不能修改' if File.exist?( '/boot/lock' )
end

def errmsg( msg = nil, contents = {} )
  Oj.dump({
    success: false,
    msg: msg
  }.merge( contents ))
end

def success( contents = {} )
  Oj.dump({
    success: true
  }.merge( contents ))
end
