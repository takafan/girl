require 'girl/custom'

module Girl
  class ProxyCustom
    include Custom

    def initialize( im )
      @im = im
    end

    def hello
      @im
    end

  end
end
