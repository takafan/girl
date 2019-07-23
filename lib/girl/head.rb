module Girl
  PACK_SIZE = 1448              # 包大小 1492(PPPoE MTU) - 20(IPv4 head) - 8(UDP head) - 8(source/dest id) - 8(pack id) = 1448
  CHUNK_SIZE = PACK_SIZE * 1000 # 块大小
  RESEND_AFTER = 1              # 几秒后重传
  QUEUE_LIMIT = 4000            # 重传队列上限，到达上限暂停写（只重传，不写新的）
  RESUME_BELOW = 500            # 降到多少以下恢复写
  RESEND_INTERVAL = 0.01        # 检查重传间隔
  RESEND_LIMIT = 20             # 重传次数上限
  RESUME_INTERVAL = 0.1         # 检查恢复写间隔
  HEARTBEAT = 1
  A_NEW_SOURCE = 2
  PAIRED = 3
  CONFIRM_A_PACK = 4
  DEST_FIN = 5
  SOURCE_FIN = 6
  CONFIRM_DEST_FIN = 7
  CONFIRM_SOURCE_FIN = 8
  TUND_FIN = 9
  TUN_FIN = 10
  CTL_CLOSE_SOCK = [ 1 ].pack( 'C' )
  CTL_RESUME = [ 2 ].pack( 'C' )
end
