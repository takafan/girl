module Girl
  module Custom
    ALT = { '.' => '/', '/' => '.' }

    def encode( data )
      swap( data )
    end

    def decode( data )
      swap( data )
    end

    def swap( data )
      data.gsub( /\.|\// ){ | c | ALT[ c ] }
    end

    def encode2( data )
      data.reverse
    end

    def decode2( data )
      data.reverse
    end
  end
end
