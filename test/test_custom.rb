require File.expand_path( '../pretty.rb', __FILE__ )
require File.expand_path( '../../lib/girl/custom.rb', __FILE__ )
include Girl::Custom

$pretty_total = 4

data = 'abcdefghij' * 1024 * 1024 * 10
puts "data.bytesize #{ data.bytesize }"

t0 = Time.new
encoded = encode( data )
puts "encode #{ Time.new - t0 }s"
puts "encoded.bytesize #{ encoded.bytesize }"

t0 = Time.new
data2, part = decode( encoded )
puts "decode #{ Time.new - t0 }s"
pretty eval "data2 == data"

data3 = ''
part = ''
i = 0

loop do
  chunk = encoded[ i, 65535 ]
  break if chunk.nil? || chunk.empty?

  print '.'
  _data, part = decode( part + chunk )

  data3 << _data
  i += chunk.bytesize
end

pretty eval "data3 == data"

encoded_p1 = encoded[ 0..-2 ]
encoded_p2 = encoded[ -1 ]

t0 = Time.new
p1, part = decode( encoded_p1 )
puts "part #{ part } expect #{ part[ 0 ].unpack( 'C' ).first - 31 } received #{ part[ 1..-1 ].bytesize }"
p2, part = decode( part + encoded_p2 )
data4 = p1 + p2
pretty eval "part.empty? && ( data4 == data )"

msg = '{"k":"v"}'
count = 10
encoded = encode_a_msg( msg ) * count
t0 = Time.new
encoded_p1 = encoded[ 0..-2 ]
encoded_p2 = encoded[ -1 ]
t0 = Time.new
p1, part = decode_to_msgs( encoded_p1 )
puts "p1.size #{ p1.size } #{ p1[ 0 ] }"
puts "part #{ part } expect #{ part[ 0 ].unpack( 'C' ).first - 31 } received #{ part[ 1..-1 ].bytesize }"
p2, part = decode_to_msgs( part + encoded_p2 )
puts "p2.size #{ p2.size } #{ p2[ 0 ] }"
pretty eval "part.empty? && ( p1.size + p2.size == count )"
