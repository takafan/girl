module Girl
  class Hex
    def hello
      :hello
    end

    def check( data, addrinfo )
      :success
    end

    def swap( data )
      # overwrite me, you'll be free
      data
    end

    def encode( data )
      data
    end

    def decode( data )
      data
    end
  end
end
