module Girl
  class Hex
    def swap( data )
      # overwrite me, you'll be free
      data
    end

    def mix( data )
      data
    end

    def decode( data, addrinfo )
      unless data
        return {
          success: false,
          error: 'missing data'
        }
      end

      dst_family, dst_port, dst_host = data.unpack( 'nnN' )

      {
        success: true,
        dst_addr: Socket.sockaddr_in( dst_port, dst_host )
      }
    end
  end
end
