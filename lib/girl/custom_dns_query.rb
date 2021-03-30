module Girl
  module CustomDnsQuery
    def encode( data )
      data.reverse
    end

    def decode( data )
      data.reverse
    end
  end
end
