module Girl
  READ_SIZE             = 1024 * 1024       # 一次读多少
  WBUFF_LIMIT           = 100 * 1024 * 1024 # 写前上限，超过上限暂停读
  RESUME_BELOW          = WBUFF_LIMIT / 2   # 降到多少以下恢复读
  EXPIRE_NEW            = 5                 # 多久没有建立通道，过期
  EXPIRE_AFTER          = 300               # 多久没有新流量，过期
  RESET_TRAFF_DAY       = 1                 # 流量计数重置日，0为不重置
  CHECK_TRAFF_INTERVAL  = 86400             # 检查今天是否是流量计数重置日间隔
  CHECK_EXPIRE_INTERVAL = 5                 # 检查过期间隔
  CHECK_RESUME_INTERVAL = 1                 # 检查恢复读间隔
  RESOLV_CACHE_EXPIRE   = 300               # dns查询结果缓存多久过期
  HELLO                 = 1
  TUND_PORT             = 2
  A_NEW_SOURCE          = 3
  PAIRED                = 4
  DEST_STATUS           = 5
  SOURCE_STATUS         = 6
  MISS                  = 7
  FIN1                  = 8
  GOT_FIN1              = 9
  FIN2                  = 10
  GOT_FIN2              = 11
  TUND_FIN              = 12
  TUN_FIN               = 13
  IP_CHANGED            = 14
  SINGLE_MISS           = 15
  RANGE_MISS            = 16
  CONTINUE              = 17
  IS_RESEND_READY       = 18
  RESEND_READY          = 19
  RESOLV                = 20
  RESOLVED              = 21
  HEARTBEAT             = 22
  TRAFF_INFOS           = 101
  SEPARATE              = "\r\n\r\n"
  HTTP_OK               = "HTTP/1.1 200 OK\r\n\r\n"
  RESERVED_ROUTE = <<EOF
0.0.0.0/8
10.0.0.0/8
127.0.0.0/8
169.254.0.0/16
172.16.0.0/12
192.168.0.0/16
255.255.255.255/32
EOF
  CONSTS = %w[
    READ_SIZE
    WBUFF_LIMIT
    RESUME_BELOW
    EXPIRE_NEW
    EXPIRE_AFTER
    CHECK_EXPIRE_INTERVAL
    CHECK_RESUME_INTERVAL
    RESOLV_CACHE_EXPIRE
  ]
end
