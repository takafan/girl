module Girl
  BACKLOG              = 512               # 听队列大小，满后掉SYN包
  RLIMIT               = 1024              # sock数上限
  READ_SIZE            = 1 * 1024 * 1024   # 一次最多读多少
  WBUFF_LIMIT          = 10 * 1024 * 1024  # 写前上限，超过上限暂停读另一头
  CLOSE_ABOVE          = 100 * 1024 * 1024 # 超过多少强制关闭
  HEARTBEAT_INTERVAL   = 10                # 心跳间隔
  CHECK_TRAFF_INTERVAL = 3600              # 多久检查一次，今天是不是流量计数重置日
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
