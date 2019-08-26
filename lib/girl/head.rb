module Girl
  PACK_SIZE             = 1328             # 包大小 1400(console MTU) - 8(PPPoE header) - 40(IPv6 header) - 8(UDP header) - 8(source/dest id) - 8(pack id) = 1328
  CHUNK_SIZE            = PACK_SIZE * 1000 # 块大小
  WBUFFS_LIMIT          = 1000             # 写前上限，超过上限结一个块
  WMEMS_LIMIT           = 100_000          # 写后上限，到达上限暂停写
  RESUME_BELOW          = 50_000           # 降到多少以下恢复写
  EXPIRE_AFTER          = 1800             # 多久过期
  STATUS_INTERVAL       = 0.3              # 发送状态间隔
  SEND_STATUS_UNTIL     = 20               # 持续的告之对面状态，直到没有流量往来，持续多少秒
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
  CTL_CLOSE             = 1
  CTL_RESUME            = 2
end
