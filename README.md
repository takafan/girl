# girl - while internet is evil, here's a girl.

妹子传的快。

想过没有？下载一个文件，从近的地方下载，很快，但从远的地方下载，慢，慢一点我也不会怀疑，问题是慢很多，几兆每秒，慢成几十K，几K。什么原因？是线路不行吗？

是tcp不行。

妹子带来一套现代的传输策略，tcp慢成几十K，几K，同一条线路，妹子依然几兆。

妹子的目标不是替换tcp，是替换tcp猴不住的那一段，远距离传输：

```
流量 -> http代理 -> 妹子近端 ----------> 远端 -> 目的地
```

通过http代理，但不同于http代理，妹子在近端（内网或者本机）接流量，把流量掌控在出门前。接着把流量打包成udp，传往远端（vps），并保证其可靠。

你可以控制去和不去，借助一个域名列表，和一个ip段列表。完整的路线图：

```
流量 -> http代理 -> 妹子近端 -> 域名命中remotes.txt？-- hit ----------> 远端 -> 解析域名 -> 目的地
                                                  \
                                                   `- not hit -> 解析域名 -> ip命中directs.txt？-- hit -----> 目的地
                                                                                              \
                                                                                               `- not hit -----> 远端 -> 目的地
```

不细说了，起飞了。

## 快

还是要细的。下面我很慢的，聊一聊快。可以不看。

远距离传输，掉包是常态，掉包，就需要重传，下载快不快，取决于重传策略妙不妙。tcp的重传策略是超时主动重传，搭配迄今为止的10来个补丁，也叫拥控算法，供你选一，但它们都不能应对严重掉包。

tcp不够现代的地方，首先是单发确认，收到很多，但只回复第一个断开的那个号码，只能消比它小的，如果你一秒钟掉一千个包，你要急死。

于是一个扩展补丁，SACK来了，回复的时候可以多确认几个头尾，对面得以跳跃的消缓存，但，仅仅是多确认几个，因为它是一个tcp选项，有40个字节的限制，你一秒钟掉一千个包，你还是急死。

我看不下去了，我给流量打上序号，打包成udp，在应用层重传。我一边收，一边半秒被告知一次对面的状态，例如，收到1-5，和跳号的8，这半秒被告知发到10，得出6-7，9-10两个号码段，要求对面重传。我称之为：被动重传。

被动重传做到了及时消缓存，或者说及时腾空间。除了腾空间，能不能加空间？

妙的来了，我把缓存分成写前和写后，写前，是准备发给对面的流量，发了变成写后，供重传用。写前可以自动扩展至文件系统，例如下载一个5个G的游戏，由于远端下载游戏要比传给近端快，游戏被分块暂存在远端硬盘上，再一块一块的传给近端，一块是1.3M，读进内存传，传完取下一块，也就是说超过1.3M的文件只会有1.3M在内存里。剩下的内存全用来放写后。只当传巨大文件，对面来不及收，使得写后到达上限，这时才限制一下内存：暂停取写前，降下去后恢复。

妹子比tcp快多少？不堵的线路，电信gia线路美国服务器，curl下载服务器上的文件，大家都很快，hybla 13.6M/s，bbr 13.4M，cubic 12.7M，妹子9.1M，稍微慢一点。

换一台堵的，电信老线路，单程cn2美国服务器，hybla降到80K，bbr降到10K，cubic降到4K，在tcp全体投降的状态下，妹子依然8M，比hybla快100倍，比bbr快800倍，比cubic快2000倍。

## udp怎么办

udp是另一个世界。可以不看。

udp的快，是指：低延迟。如果家用电信线路不行，你希望通过代理换条路，那么这条路需要比原路短。细点说，你家到代理服务器的ping值，加代理服务器到目的地的ping值，小于直连，代理才有意义。为了追求低延迟，udp很需要区分国内外。目的地在国外，可以给它找条更短的路，目的地在国内，直连就是最快的。

但udp不能区分国内外。因为p2p的存在。要是把国内ip段设为直连，采用p2p联机的游戏会怎么样：游戏匹配服务器在海外，匹配到国内玩家，他从他洞里出来穿你（映射到远端的）洞，通。你却不走打好的洞突然直连穿他，不通。因此，要么不走，要么统统走，并且接受：和远的人连变快的同时，和近的人连变慢了。

并且，现实中，udp代理是不存在的。首先，http代理不支持udp，也就是说，ios，android，ps4，switch，不支持。然后，windows和macos可设socks5，socks5支持udp。但走不走代理，还是由应用程序实现，实现socks5，有的，但实现socks5中的UDP ASSOCIATE部分，没见过。所以，udp代理是不存在的。想使p2p联机变快，办法只有一个：vpn。

另附一个黑客向的办法：借助iptables把udp跳转到自己的端口，然后去/proc/net/nf_conntrack里找出源目的地，透明转发。

## 使用篇

分别在两端装：

```bash
gem install girl
```

远端：

```ruby
# proxyd.rb
require 'girl/proxyd'

Girl::Proxyd.new '/etc/girl.conf.json'
```

```bash
ruby proxyd.rb
```

近端：

```ruby
# proxy.rb
require 'girl/proxy'

Girl::Proxy.new '/boot/girl.conf.json'
```

```bash
ruby proxy.rb
```

girl.conf.json的格式：

```javascript
// girl.conf.json
{
    "proxy_port": 6666,                   // 代理服务，近端（本地）端口
    "proxyd_host": "1.2.3.4",             // 代理服务，远端服务器
    "proxyd_port": 6060,                  // 代理服务，远端端口
    "direct_path": "girl.direct.txt",     // 直连ip段
    "remote_path": "girl.remote.txt",     // 交给远端解析的域名列表
    "proxy_tmp_dir": "/tmp/girl.proxy",   // 近端缓存根路径
    "proxyd_tmp_dir": "/tmp/girl.proxyd", // 远端缓存根路径
    "im": "girl",                         // 标识，用来识别近端
    "worker_count": 4                     // 子进程数，默认取cpu个数
}
```

获取注册在亚太的CN的ip段：

```bash
curl 'http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest' | grep ipv4 | grep CN | awk -F\| '{ printf("%s/%d\n", $4, 32-log($5)/log(2)) }' > girl.direct.txt
```

girl.remote.txt的格式：

```txt
google.com
googleusercontent.com
gstatic.com
twimg.com
twitter.com
youtube.com
ytimg.com
```

很多网站都流行把静态资源放到额外的一个域名下，需要自行f12探索一下。

## 对抗邪恶

实际是解决2个问题：

1. dns查询得到正确的ip。
2. tcp流量正常的到达目的地。

在国内，满足：特定域名+53端口，dns查询包会被邪恶掉，到不了远端。同样，含特定域名的tcp流量会被邪恶掉。

办法是混淆域名。哎，这么简单，同行们都搞复杂了。

覆盖下面两个方法即可：

```ruby
def encode( data )
  # overwrite me, you'll be free
  data
end

def decode( data )
  data
end
```

例如：

```ruby
def encode( data )
  data.reverse
end

def decode( data )
  data.reverse
end
```

完整例子：

```ruby
# proxyd.rb
require 'girl/proxyd'

module Girl
  module Custom
    def encode( data )
      data.reverse
    end

    def decode( data )
      data.reverse
    end
  end
end

Girl::Proxyd.new '/etc/girl.conf.json'
```

```ruby
# proxy.rb
require 'girl/proxy'

module Girl
  module Custom
    def encode( data )
      data.reverse
    end

    def decode( data )
      data.reverse
    end
  end
end

Girl::Proxy.new '/boot/girl.conf.json'
```

https的第一段流量含明文域名，之后本身就是乱码。ssh的第一段流量是明文版本号，之后本身就是乱码。因此妹子的加解密方法只作用第一段流量。
