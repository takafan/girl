require 'girl/custom'

module Girl
  class ProxydCustom
    include Custom

    def check( data, addrinfo )
      :success
    end

  end
end
