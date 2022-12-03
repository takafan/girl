$point = 0
$success = 0
$fail = 0
$pretty_count = 0
$pretty_total = 0

class String
  def colorize(color_code)
    "\e[#{color_code}m#{self}\e[0m"
  end

  def red
    colorize(31)
  end

  def green
    colorize(32)
  end

  def yellow
    colorize(33)
  end

  def blue
    colorize(34)
  end

  def pink
    colorize(35)
  end

  def light_blue
    colorize(36)
  end

  def reverse_color
    "\e[7m#{self}\e[27m"
  end
end

def pretty( is_ok )
  $point += 1
  output = ''

  puts
  output << $point.to_s
  output << '. '

  if is_ok then
    output << '✓'
    $success += 1
  else
    output << '✗'
    $fail += 1
  end
  
  puts is_ok ? output.green : output.red
  puts

  $pretty_count += 1
  show_stat if $pretty_count == $pretty_total
end

def show_stat
  puts
  print 'success: '.green
  puts $success.to_s.green
  print '   fail: '.red
  puts $fail.to_s.red
end
