class ConcurrentHash < Hash
  def initialize
    super
    @mutex = Mutex.new
  end

  def []( *args )
    @mutex.synchronize { super }
  end

  def []=( *args )
    @mutex.synchronize { super }
  end

  def delete( *args )
    @mutex.synchronize { super }
  end

  def each( *args )
    @mutex.synchronize { super }
  end

  def clear( *args )
    @mutex.synchronize { super }
  end
end
