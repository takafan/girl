module Girl
  PACK_SIZE             = 1448             # 包大小 1492(PPPoE MTU) - 20(IPv4 head) - 8(UDP head) - 8(source/dest id) - 8(pack id) = 1448
  CHUNK_SIZE            = PACK_SIZE * 1000 # 块大小
  WMEMS_LIMIT           = 100_000          # 写后缓存上限，到达上限暂停写
  RESUME_BELOW          = 50_000           # 降到多少以下恢复写
  CHECK_EXPIRE_INTERVAL = 900              # 检查过期间隔
  EXPIRE_AFTER          = 1800             # 多久过期
  HEARTBEAT_INTERVAL    = 59               # 心跳间隔
  STATUS_INTERVAL       = 0.3              # 发送状态间隔
  SEND_STATUS_UNTIL     = 10               # 持续的告之对面状态，直到没有流量往来，持续多少秒
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
  CTL_CLOSE_SOCK        = [ 1 ].pack( 'C' )
  CTL_RESUME            = [ 2 ].pack( 'C' )
end
