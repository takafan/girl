module Girl
  PACK_SIZE                  = 1328                 # 包大小 1400(console MTU) - 8(PPPoE header) - 40(IPv6 header) - 8(UDP header) - 8(pack id) - 8(src id) = 1328
  READ_SIZE                  = PACK_SIZE * 100      # 一次读多少
  WMEMS_LIMIT                = 100_000              # 写后上限，超过上限暂停读src/dst
  RESUME_BELOW               = 50_000               # 降到多少以下恢复读
  EXPIRE_NEW                 = 10                   # 创建之后多久没有流量进来，过期
  EXPIRE_AFTER               = 300                  # 多久没有新流量，过期
  CHECK_EXPIRE_INTERVAL      = 30                   # 检查过期间隔
  CHECK_STATUS_INTERVAL      = 0.5                  # 发送状态间隔
  SEND_STATUS_UNTIL          = 10                   # 持续的告之对面状态，直到没有流量往来，持续多少秒
  MULTI_MISS_SIZE            = 80                   # 几个miss段打一个包
  MISS_RANGE_LIMIT           = MULTI_MISS_SIZE * 10 # miss段上限，达到上限忽略要后面的段
  CONFUSE_UNTIL              = 5                    # 混淆前几个包
  RESOLV_CACHE_EXPIRE        = 300                  # dns查询结果缓存多久过期
  TUND_PORT                  = 1
  HEARTBEAT                  = 2
  A_NEW_SOURCE               = 3
  PAIRED                     = 4
  DEST_STATUS                = 5
  SOURCE_STATUS              = 6
  MISS                       = 7
  FIN1                       = 8
  GOT_FIN1                   = 9
  FIN2                       = 10
  GOT_FIN2                   = 11
  TUND_FIN                   = 12
  TUN_FIN                    = 13
  IP_CHANGED                 = 14
  MULTI_MISS                 = 15
  HTTP_OK                    = "HTTP/1.1 200 OK\r\n\r\n"
  # https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
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
