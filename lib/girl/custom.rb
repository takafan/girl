module Girl
  module Custom

    A_NEW_SOURCE        = 'A'
    HELLO               = 'H'
    PAIRED              = 'P'
    SEP                 = ','

    def encode( data )
      buff = ''
      i = 0

      loop do
        chunk = data[ i, 95 ]
        break if chunk.nil? || chunk.empty?

        chunk = chunk.reverse
        len = chunk.bytesize
        packet = [ len + 31 ].pack( 'C' ) + chunk
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

        len = h.unpack( 'C' ).first - 31

        if ( len <= 0 ) || ( len > 95 ) then
          puts "#{ Time.new } decode invalid len? #{ h.inspect }"
          break
        end

        chunk = data[ i + 1, len ]
        break unless chunk

        if chunk.bytesize < len then
          part = [ len + 31 ].pack( 'C' ) + chunk
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

      if ( len == 0 ) || ( len > 224 ) then
        puts "#{ Time.new } encode a msg invalid len? #{ data.inspect }"
        return ''
      end

      [ len + 31 ].pack( 'C' ) + data.reverse
    end

    def decode_to_msgs( data )
      msgs = []
      part = ''
      i = 0

      loop do
        h = data[ i ]
        break unless h

        len = h.unpack( 'C' ).first - 31

        if len <= 0 then
          puts "#{ Time.new } decode to msgs invalid len? #{ h.inspect }"
          break
        end

        chunk = data[ i + 1, len ]
        break unless chunk

        if chunk.bytesize < len then
          part = [ len + 31 ].pack( 'C' ) + chunk
          break
        end

        chunk = chunk.reverse
        msgs << chunk
        i += ( len + 1 )
      end

      [ msgs, part ]
    end

    def encode_im( data )
      data.reverse
    end

    def decode_im( data )
      data.reverse
    end
  end
end
