# girl - while internet is evil, here's a girl.

妹子解决2个问题：

1. dns查询得到正确的ip。
2. tcp流量正常的到达目的地。

同时，她加速tcp传输。加速海外游戏。

画图说明，通常：

```
流量 ----> 网关 ---------------> 目的地
```

为了解决开篇2个问题：

```
流量 ----> 网关（点对点近端） ---------------> 点对点远端 ----> 目的地
```

妹子加速tcp传输，不是单纯的换线路（新线路比原线路快），妹子带来一套现代的传输策略，她比tcp快。

举个例子，你有一台服务器，从近的地方下载服务器上的文件，有几兆每秒，但从远的地方，只有几十k，几k。而妹子依然几兆。

妹子还支持udp转发，这可以加速任何用p2p实现联机的游戏，特别是海外玩家多的那种，比如街霸、吃鸡、人类一败涂地。

妹子是透明的，把她安装在路由器（近端）以及你的vps上（远端），你的任何电子设备照常连网，原地起飞。

## 快

下面我很慢的，聊一聊快。

远距离传输，掉包是常态，掉包，就需要重传，下载快不快，取决于重传策略妙不妙。tcp的重传策略是超时主动重传，搭配迄今为止的10来个补丁，也叫拥控算法，供你选一，但它们都不能应对严重掉包。

tcp不够现代的地方，首先是单发确认，收到很多，但只回复第一个断开的那个号码，只能消比它小的，如果你一秒钟掉一千个包，你要急死。

于是一个扩展补丁，SACK来了，回复的时候可以多确认几个头尾，对面得以跳跃的消缓存，但，仅仅是多确认几个，因为它是一个tcp选项，有40个字节的限制，你一秒钟掉一千个包，你还是急死。

我看不下去了，我给流量打上序号，打包成udp，在应用层重传。我一边收，一边半秒被告知一次对面的状态，例如，收到1-5，和跳号的8，这半秒被告知发到10，得出6-7，9-10两个号码段，要求对面重传。简称：被动重传。

被动重传做到了及时消缓存，或者说及时腾空间。除了腾空间，能不能加空间？

妙的来了，我把缓存分成写前和写后，写前，是准备发给对面的流量，发了变成写后，供重传用。写前可以自动扩展至文件系统，例如下载一个5个G的游戏，由于远端下载游戏要比传给近端快，游戏被分块暂存在远端硬盘上，再一块一块的传给近端，一块是1.3M，读进内存传，传完取下一块，也就是说超过1.3M的文件只会有1.3M在内存里。剩下的内存全用来放写后，这样我的窗就很大，只当传巨大文件，对面来不及收，使得写后到达上限，这时才触发窗口限制：暂停取写前，降下去后恢复。

妹子比tcp快多少？不堵的线路，电信gia线路美国服务器，curl下载服务器上的文件，大家都很快，hybla 13.6M/s，bbr 13.4M，cubic 12.7M，妹子9.1M，稍微慢一点。

换一台堵的，电信老线路，单程cn2美国服务器，hybla降到80K，bbr降到10K，cubic降到4K，在tcp全体投降的状态下，妹子依然8M，比hybla快100倍，比bbr快800倍，比cubic快2000倍。

## 使用

分别在两端装：

```bash
gem install girl
```

## 1. dns查询得到正确的ip

```
dns query -> resolv ---- default -------------------> 114.114.114.114
                    \
                     `-- hit list --> encode --> resolvd ---> 8.8.8.8
```

远端：

```ruby
require 'girl/resolvd'

Girl::Resolvd.new( 7070 ).looping
```

近端：

```ruby
require 'girl/resolv'

Girl::Resolv.new( 1717, [ '114.114.114.114' ], 'your.server.ip', 7070, [ 'google.com' ] ).looping
```

```bash
dig google.com @127.0.0.1 -p1717
```

在国内，满足：特定域名+53端口，dns查询包会被邪恶掉，到不了远端。办法是混淆域名，或者换个端口。

diy加解密，覆盖下面两个方法即可：

```ruby
def encode( data )
  # overwrite me, you'll be free
  data
end

def decode( data )
  data
end
```

## 2. tcp流量正常的到达目的地

```
tcp traffic -> iptables ---- cn ip -------------------------------> 微博
                        \
                         `-- not cn --> tun --> encode --> tund --> 谷歌
                                                          ,
                                                      cache
```

远端：

```ruby
require 'girl/tund'

Girl::Tund.new( 9090 ).looping
```

近端：

```ruby
require 'girl/tun'

Girl::Tun.new( 'your.server.ip', 9090, 1919 ).looping
```

```bash
dig +short www.google.com @127.0.0.1 -p1717 # got 216.58.217.196

iptables -t nat -A OUTPUT -p tcp -d 216.58.217.196 -j REDIRECT --to-ports 1919

curl https://www.google.com/
```

同样在国内，含特定域名的tcp流量会被邪恶掉。办法也是混淆域名。和上面一样，覆盖加解密方法。

https的第一段流量含明文域名，之后本身就是乱码。ssh的第一段流量是明文版本号，之后本身就是乱码。因此妹子的加解密方法只作用于第一段流量。

相比别的对抗邪恶的办法，妹子没有特征，不加密（或者你自定义）。

## 3. 转发udp

```
udp traffic -> iptables ---- cn ip ------------------------------> 游戏服务器
                        \
                         `-- not cn --> udp ------------> udpd --> 海外游戏服务器
```

远端：

```ruby
require 'girl/udpd'

Girl::Udpd.new( 3030 ).looping
```

近端：

```ruby
require 'girl/udp'

Girl::Udp.new( 'your.server.ip', 3030, 1313 ).looping
```

```bash
iptables -t nat -A PREROUTING -p udp -d game.server.ip -j REDIRECT --to-ports 1313
```

想加速任何海外游戏/网站，同时直连任何国内游戏/网站，根据：

https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml

http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest

把保留ip段和注册在亚太的CN的ip段-j RETURN，其余-j REDIRECT到妹子端口。

## 4. 树莓派

把妹子安装在树莓派上，你就得到了一台可能是目前地球上最快的（性价比最高的）（加速任何海外游戏的）（对抗邪恶的）路由器。

![妹子路由器1](http://89.208.243.143/pic1.jpg)

![妹子路由器3](http://89.208.243.143/pic3.jpg)
