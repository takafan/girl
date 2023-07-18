require File.expand_path( '../helper.rb', __FILE__ )
require File.expand_path( '../../lib/girl/custom.rb', __FILE__ )
require File.expand_path( '../../lib/girl/head.rb', __FILE__ )
include Girl::Custom

# puts "Girl::Custom::WAVE #{ Girl::Custom::WAVE }"
# puts "Girl::READ_SIZE #{ Girl::READ_SIZE }"

data = 'abcdefghij' * 1024 * 1024
# puts "data.bytesize #{ data.bytesize }"

encoded = ''
i = 0

Girl::Custom::WAVE.times do
  data2 = data[ i, Girl::READ_SIZE ]
  encoded << encode( data2 )
  i += Girl::READ_SIZE
end

encoded << Girl::Custom::TERM
encoded << data[ i..-1 ]
# puts "encoded.bytesize #{ encoded.bytesize }"

decoded, part = decode( encoded )
puts_result( 'decode', decoded == data )

decoded = ''
part = ''
i = 0

loop do
  data2 = encoded[ i, Girl::READ_SIZE ]

  if part != Girl::Custom::TERM then
    data2, part = decode( part + data2 )
    # puts "part #{ part.inspect } #{ part.bytesize }"
  end

  decoded << data2
  i += Girl::READ_SIZE
  break if i >= encoded.bytesize
end

puts_result( 'partial decode', decoded == data )
