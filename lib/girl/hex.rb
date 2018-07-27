module Girl
  class Hex
    def swap(data)
      # overwrite me, you'll be free
      data
    end

    def mix(data, dst_host, dst_port)
      data.prepend("#{dst_host}:#{dst_port}\n")
    end
  end
end
