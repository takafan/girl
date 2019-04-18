module Girl
  class Hex
    def hello
      :hello
    end

    def check( data, addrinfo )
      :success
    end

    def encode( data )
      # overwrite me, you'll be free
      data
    end

    def decode( data )
      data
    end
  end
end
