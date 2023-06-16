module Girl
  READ_SIZE             = 1024 * 1024      # 一次读多少
  WBUFF_LIMIT           = 20 * 1024 * 1024 # 写前上限，超过上限暂停读
  RESUME_BELOW          = WBUFF_LIMIT / 2  # 降到多少以下恢复读
  CHUNK_SIZE            = 65535            # 按块加解密，块尺寸上限，不超过65535
  EXPIRE_NEW            = 5                # 多久没有建立通道，过期
  EXPIRE_CONNECTING     = 2                # 连接中，多久没连上过期
  EXPIRE_AFTER          = 86400            # 多久没有新流量，过期
  EXPIRE_TCP            = 60               # 多久没有收到控制流量，在A_NEW_SOURCE超时时过期tcp
  RESET_TRAFF_DAY       = 1                # 流量计数重置日，0为不重置
  CHECK_TRAFF_INTERVAL  = 86400            # 检查今天是否是流量计数重置日间隔
  CHECK_EXPIRE_INTERVAL = 3600             # 检查过期间隔
  RESOLV_CACHE_EXPIRE   = 300              # dns查询结果缓存多久过期
  PING_TIMEOUT          = 2                # tun建立连接后多久没有响应，超时
  RENEW_CTL_INTERVAL    = 10               # p1心跳间隔
  ROOM_TITLE_LIMIT      = 16               # 房间名称字数

  HTTP_OK = "HTTP/1.1 200 OK\r\n\r\n"
  RESERVED_ROUTE = <<EOF
0.0.0.0/8
10.0.0.0/8
127.0.0.0/8
169.254.0.0/16
172.16.0.0/12
192.168.0.0/16
255.255.255.255/32
EOF

end
