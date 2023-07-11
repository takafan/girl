module Girl
  module Custom

    A_NEW_SOURCE = 'A'
    CHUNK_SIZE   = 255
    HELLO        = 'H'
    OFFSET       = 0
    PAIRED       = 'P'
    SEP          = ','
    TERM         = [ 0 ].pack( 'C' )
    WAVE         = 2

    def encode( data )
      # puts "debug encode #{ data.inspect }"
      buff = ''
      i = 0

      loop do
        chunk = data[ i, CHUNK_SIZE ]
        break if chunk.nil? || chunk.empty?

        chunk = chunk.reverse
        len = chunk.bytesize
        packet = [ len + OFFSET ].pack( 'C' ) + chunk
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

        if h == TERM then
          buff << data[ ( i + 1 )..-1 ] if data.bytesize > ( i + 1 )
          part = TERM
          break
        end

        len = h.unpack( 'C' ).first - OFFSET

        if ( len <= 0 ) || ( len > CHUNK_SIZE ) then
          puts "#{ Time.new } decode invalid len? #{ h.inspect }"
          break
        end

        chunk = data[ i + 1, len ]
        break unless chunk

        if chunk.bytesize < len then
          part = [ len + OFFSET ].pack( 'C' ) + chunk
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

      if ( len == 0 ) || ( len > CHUNK_SIZE ) then
        puts "#{ Time.new } encode a msg invalid len? #{ data.inspect }"
        return ''
      end

      [ len + OFFSET ].pack( 'C' ) + data.reverse
    end

    def decode_to_msgs( data )
      msgs = []
      part = ''
      i = 0

      loop do
        h = data[ i ]
        break unless h

        len = h.unpack( 'C' ).first - OFFSET

        if len <= 0 || ( len > CHUNK_SIZE ) then
          puts "#{ Time.new } decode to msgs invalid len? #{ h.inspect }"
          break
        end

        chunk = data[ i + 1, len ]
        break unless chunk

        if chunk.bytesize < len then
          part = [ len + OFFSET ].pack( 'C' ) + chunk
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
