require 'girl/custom'

module Girl
  class ProxydCustom
    include Custom

    def check( data )
      :success
    end

  end
end
