module Girl
  READ_SIZE             = 1024 * 1024       # 一次读多少
  WBUFF_LIMIT           = 100 * 1024 * 1024 # 写前上限，超过上限暂停读
  RESUME_BELOW          = WBUFF_LIMIT / 2   # 降到多少以下恢复读
  SEND_HELLO_COUNT      = 10                # hello最多发几次
  EXPIRE_AFTER          = 300               # 多久没有新流量，过期
  CHECK_EXPIRE_INTERVAL = 30                # 检查过期间隔
  CHECK_RESUME_INTERVAL = 1                 # 检查恢复读间隔
  RESOLV_CACHE_EXPIRE   = 300               # dns查询结果缓存多久过期
  TUND_PORT             = 1
  HEARTBEAT             = 2
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
  HTTP_OK               = "HTTP/1.1 200 OK\r\n\r\n"
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
  CONSTS = %w[
    READ_SIZE
    WBUFF_LIMIT
    RESUME_BELOW
    SEND_HELLO_COUNT
    EXPIRE_AFTER
    CHECK_EXPIRE_INTERVAL
    CHECK_RESUME_INTERVAL
    RESOLV_CACHE_EXPIRE
  ]
end
