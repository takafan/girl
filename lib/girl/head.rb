module Girl
  PACK_SIZE = 1456 # 1492(PPPoE MTU) - 20(IPv4 head) - 8(UDP head) - 8(pack id) = 1456
  CHUNK_SIZE = PACK_SIZE * 1000
  MEMORIES_LIMIT = 10_000 # 写后缓存上限
  RESEND_LIMIT = 20 # 重传次数上限
end
