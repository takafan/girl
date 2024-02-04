module Girl
  BACKLOG                   = 512              # 听队列大小，满后掉SYN包
  RLIMIT                    = 1024             # sock数上限，淘汰池要求RLIMIT不低于1024
  READ_SIZE                 = 4 * 1024 * 1024  # 一次读多少
  WBUFF_LIMIT               = 30 * 1024 * 1024 # 写前上限，超过上限暂停读
  RESUME_BELOW              = WBUFF_LIMIT / 2  # 降到多少以下恢复读
  EXPIRE_APP_AFTER          = 86400            # app多久没有新流量，过期
  CHECK_TRAFF_INTERVAL      = 3600             # 检查今天是否是流量计数重置日间隔
  CHECK_APP_EXPIRE_INTERVAL = 3600             # 检查app过期间隔
  RESOLV_CACHE_EXPIRE       = 600              # dns查询结果缓存多久过期
  RENEW_CTL_INTERVAL        = 10               # p1心跳间隔
  ROOM_TITLE_LIMIT          = 16               # 房间名称字数
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
