module Girl
  class Hex
    def initialize
    end
    
    def swap(data)
      data
    end
    
    def peek_domain(data, dst_host, dst_port)
      [ 
        data.prepend("#{dst_host}:#{dst_port}\n"), 
        domain = nil 
      ]
    end
  end
end
