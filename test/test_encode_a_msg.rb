require File.expand_path( '../helper.rb', __FILE__ )
require File.expand_path( '../../lib/girl/custom.rb', __FILE__ )
require File.expand_path( '../../lib/girl/head.rb', __FILE__ )
include Girl::Custom

msg = 'A,12420043719413841883,ef67fc04ce9b132c2b32-8aedd782b7d22cfe0d1146da69a52436.r14.cf1.rackcdn.com:80'
count = 10
encoded = encode_a_msg( msg ) * count
encoded1 = encoded[ 0..-2 ]
encoded2 = encoded[ -1 ]

msgs1, part = decode_to_msgs( encoded1 )
# puts "msgs1.size #{ msgs1.size } part #{ part.inspect }"
msgs2, part = decode_to_msgs( part + encoded2 )
# puts "msgs2.size #{ msgs2.size } part #{ part.inspect }"

puts_result( 'encode_a_msg', msgs1.size + msgs2.size == count )
