module Girl
  class Hex
    def swap( data )
      # overwrite me, you'll be free
      data
    end

    def mix( dst_host, dst_port )
      "#{ dst_host }:#{ dst_port }\n"
    end
  end
end
