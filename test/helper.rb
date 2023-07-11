ITEM_SIZE = 20

def puts_result( item, ok )
  item = item + ' ' * ( ITEM_SIZE - item.size ) if item.size < ITEM_SIZE
  puts "* #{ item }: #{ ok }"
end
