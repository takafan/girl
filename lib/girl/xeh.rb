module Girl
  class Xeh
    def initialize(port)
    end
    
    def swap(data)
      data
    end
    
    def decode(data)
      unless data
        return { 
          success: false, 
          error: 'missing data' 
        }
      end
      
      head = data[/.+/]
      dst_host, dst_port_str = head.split(':')
      
      {
        success: true,
        data: [
          data.sub("#{head}\n", ''),
          dst_host,
          dst_port_str.to_i
        ]
      }
    end
  end
end
