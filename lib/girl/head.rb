module Girl
  BACKLOG              = 512              # 听队列大小，满后掉SYN包
  RLIMIT               = 1024             # sock数上限
  READ_SIZE            = 4 * 1024 * 1024  # 一次读多少
  WBUFF_LIMIT          = READ_SIZE * 2    # 写前上限，超过上限暂停读
  RESUME_BELOW         = READ_SIZE        # 降到多少以下恢复读
  CLOSE_ABOVE          = WBUFF_LIMIT * 3  # 超过多少强制关闭
  HEARTBEAT_INTERVAL   = 10               # 心跳间隔
  CHECK_TRAFF_INTERVAL = 3600             # 检查今天是否是流量计数重置日间隔
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
