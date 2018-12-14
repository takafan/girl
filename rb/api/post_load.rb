post '/api/load' do
  actives = {}
  loadeds = {}
  texts = {}
  measure_temp = nil

  SERVICES.each do | service |
    IO.popen( "systemctl status #{ service }" ) do | io |
      output = io.read
      loadeds[ service ] = output[ /Loaded:.+/ ]
      actives[ service ] = output[ /Active:.+/ ]
    end
  end

  CONFIG_FILES.each do | file |
    path = File.join( '/boot', file )
    texts[ file ] = File.exist?( path ) ? IO.read( path, encoding: 'utf-8' ) : ''
  end

  IO.popen( 'vcgencmd measure_temp' ) do | io |
    measure_temp = io.read.strip
  end

  success({
    loadeds: loadeds,
    actives: actives,
    texts: texts,
    measure_temp: measure_temp,
    is_locked: File.exist?( '/boot/lock' )
  })
end
