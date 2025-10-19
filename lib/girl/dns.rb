module Girl
  module Dns
    
    def pack_a_query(domain, type = 1)
      # https://www.ietf.org/rfc/rfc1035.txt
      # https://www.ietf.org/rfc/rfc3596.txt
      raise "domain may not exceed 255 chars" if domain.bytesize > 255
      raise "invalid domain" if domain =~ /[^\w\.\-]/
      data = [rand(65_535), 1, 0, 1, 0, 0, 0].pack('nCCnnnn')
      data << [pack_domain(domain), type, 1].pack('a*nn')
      data
    end
  
    def pack_domain(domain)
      data = ''
  
      domain.split('.').each do |label|
        raise "label may not exceed 63 chars" if label.bytesize > 63
        data << [label.bytesize, label].pack('Ca*')
      end
  
      data << [0].pack('C')
      data
    end
  
    def seek_dn(data, offset)
      name = ""
      datalen = data.bytesize
  
      loop do
        raise "offset is greater than datalen" if datalen < (offset + 1)
  
        len = data.unpack("@#{offset} C").first
  
        if len == 0
          offset += 1
          break
        elsif (len & 0xC0) == 0xC0
          raise "data ended before offset expand" if datalen < (offset + 2)
  
          ptr = data.unpack("@#{offset} n").first
          ptr &= 0x3FFF
          name2 = seek_dn(data, ptr).first
          raise "data is malformed" if name2.nil?
  
          name += name2
          offset += 2
          break
        else
          offset += 1
          raise "no expansion found" if datalen < (offset + len)
  
          elem = data[offset..offset + len - 1]
          name += "#{elem}."
          offset += len
        end
      end
  
      [name, offset]
    end
  
    def seek_ip(data)
      ip = nil
      answer_count = data.unpack("@6 n").first
      # puts "debug answer count #{answer_count}"
      offset = seek_question(data)
      # puts "debug offset #{offset}"
  
      answer_count.times do
        ip, offset = seek_rr_ip(data, offset)
        break if ip
      end
  
      ip
    end
  
    def seek_question(data)
      offset = 12
  
      loop do
        len = data.unpack("@#{offset} C").first
        # puts "debug len #{len} #{data[offset + 1, len]}"
        break if len == 0
        offset += (1 + len)
      end
  
      offset += 5
      offset
    end

    def seek_question_dn(data)
      id = data[0, 2]
      parts = []
      offset = 12
  
      loop do
        len = data.unpack("@#{offset} C").first
        # puts "debug len #{len} #{data[offset + 1, len]}"
        break if len == 0
        parts << data[offset + 1, len]
        offset += (1 + len)
      end
      
      type = data.unpack("@#{offset + 1} n").first
      # puts "debug id #{id.inspect} dn #{parts.join('.').inspect} type #{type}"
      [id, parts.join('.'), type]
    end
  
    def seek_rr_ip(data, offset)
      ip = nil
      name, offset = seek_dn(data, offset)
      # puts "debug seek_dn #{name}, #{offset}"
      type = data.unpack("@#{offset} n").first
      # puts "debug type #{type}"
      offset += 8
      rdlen = data.unpack("@#{offset} n").first
      # puts "debug rdlen #{rdlen}"
      offset += 2
  
      if type == 1
        raise "rdlen not 4?" if rdlen != 4
        a, b, c, d = data.unpack("@#{offset} CCCC")
        ip = "#{a}.#{b}.#{c}.#{d}"
      elsif type == 28
        tokens = data.unpack("@#{offset} n8")
        ip = format("%x:%x:%x:%x:%x:%x:%x:%x", *tokens)
      end
  
      offset += rdlen
      [ip, offset]
    end

  end
end
