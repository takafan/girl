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



# encoded_p1 = encoded[ 0..-2 ]
# encoded_p2 = encoded[ -1 ]

# t0 = Time.new
# p1, part = decode( encoded_p1 )
# puts "part #{ part.inspect } expect #{ part[ 0 ].unpack( 'C' ).first - 31 } received #{ part[ 1..-1 ].bytesize }"
# p2, part = decode( part + encoded_p2 )
# data4 = p1 + p2
# pretty eval "part.empty? && ( data4 == data )"

# msg = 'A,12420043719413841883,ef67fc04ce9b132c2b32-8aedd782b7d22cfe0d1146da69a52436.r14.cf1.rackcdn.com:80'
# count = 10
# encoded = encode_a_msg( msg ) * count
# t0 = Time.new
# encoded_p1 = encoded[ 0..-2 ]
# encoded_p2 = encoded[ -1 ]
# t0 = Time.new
# p1, part = decode_to_msgs( encoded_p1 )
# puts "p1.size #{ p1.size } #{ p1[ 0 ] }"
# puts "part #{ part.inspect } expect #{ part[ 0 ].unpack( 'C' ).first - 31 } received #{ part[ 1..-1 ].bytesize }"
# p2, part = decode_to_msgs( part + encoded_p2 )
# puts "p2.size #{ p2.size } #{ p2[ 0 ] }"
# pretty eval "part.empty? && ( p1.size + p2.size == count )"
