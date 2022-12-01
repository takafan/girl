module Girl
  module Custom
    PREFIX = "GET / HTTP/1.1\r\nHost: girl.com\r\n\r\n"

    def encode( data )
      buff = ''
      i = 0

      loop do
        chunk = data[ i, 255 ]
        break if chunk.nil? || chunk.empty?

        chunk = chunk.reverse
        len = chunk.bytesize
        packet = [ len ].pack( 'C' ) + chunk
        buff << packet
        i += len
      end

      buff
    end

    def decode( data )
      buff = ''
      part = ''
      i = 0

      loop do
        h = data[ i ]
        break unless h

        len = h.unpack( 'C' ).first

        if len == 0 then
          puts "#{ Time.new } decode zero len?"
          break
        end

        chunk = data[ i + 1, len ]
        break unless chunk

        if chunk.bytesize < len then
          part = [ len ].pack( 'C' ) + chunk
          break
        end

        chunk = chunk.reverse
        buff << chunk
        i += ( len + 1 )
      end

      [ buff, part ]
    end

    def encode_a_msg( data )
      len = data.bytesize

      if len == 0 then
        puts "#{ Time.new } encode msg zero len?"
        return ''
      end

      if len > 255 then
        puts "#{ Time.new } msg len oversize? #{ data.inspect }"
        return ''
      end

      [ len ].pack( 'C' ) + data.reverse
    end

    def decode_to_msgs( data )
      msgs = []
      part = ''
      i = 0

      loop do
        h = data[ i ]
        break unless h

        len = h.unpack( 'C' ).first

        if len == 0 then
          puts "#{ Time.new } decode to msgs zero len?"
          break
        end

        chunk = data[ i + 1, len ]
        break unless chunk

        if chunk.bytesize < len then
          part = [ len ].pack( 'C' ) + chunk
          break
        end

        chunk = chunk.reverse
        msgs << chunk
        i += ( len + 1 )
      end

      [ msgs, part ]
    end
  end
end
