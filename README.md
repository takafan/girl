# girl - while internet is evil, here's a patch.

妹子解决2个问题：

1. dns查询得到正确的ip。
2. tcp流量正常的到达目的地。

同时，她把tcp传输变快。

画图说明：

```
近端 ---------------> 远端
```

妹子分成近端-远端，可以看成一条通道。

```
近端 ---------------> 国内
    \                     
     `---- 远端 ----> 国外
```

访问国内，直连。访问国外，走通道，比直连快。

```
近端 ----- 混淆 -----> 远端 ----- 解开 -----> 目的地
```

你可以混淆流量，得以安全传输，到远端再解开。

## 快

下面我很慢的，聊一聊快。

远距离传输，掉包是常态，掉包，就需要重传，下载快不快，取决于重传策略妙不妙。tcp的重传策略是超时主动重传，搭配迄今为止的10来个补丁，也叫拥控算法，供你选一，但它们都不能应对严重掉包。

tcp不够好的地方，首先是单发确认，发送方只会被告之下一个需要的号码，或者说第一个断掉的号码，这个号码接上了，再被告之下一个。如果你一秒钟掉一千个包，你要急死。

于是一个扩展补丁，SACK来了，它可以多要几个号码，但，仅仅是多要几个，因为它是一个tcp选项，有40个字节的限制，你一秒钟掉一千个包，你还是急死。

我看不下去了，我给流量打上序号，打包成udp，在应用层重传。我一边收，一边半秒被告知一次对面的状态，例如，收到1-5，和跳号的8，这半秒被告知发到10，得出6-7，9-10两个号码段，要求对面重传。缺多少，要多少。简称：被动重传。

tcp不快，还有一个原因：有限的内存。有限的内存迫使tcp发明“窗口”，窗口满了清空或者暂停，或者快满了降速，导致它不快。

妙的来了，我把缓存分成写前和写后，写前，是准备发给对面的流量，发了变成写后，供重传用。写前可以自动扩展至文件系统，例如下载一个5个G的游戏，由于远端下载游戏要比传给近端快，游戏被分块暂存在远端硬盘上，再一块一块的传给近端，一块是1.3M，读进内存传，传完取下一块，也就是说超过1.3M的文件只会有1.3M在内存里。剩下的内存全用来放写后，这样我的窗就很大，只当传巨大文件，对面来不及收，使得写后到达上限，这时才触发窗口限制：暂停取写前，降下去后恢复。

妹子比tcp快多少？不堵的线路，电信gia线路美国服务器，curl下载服务器上的文件，大家都很快，hybla 13.6M/s，bbr 13.4M，cubic 12.7M，妹子9.1M，稍微慢一点。

换一台堵的，电信老线路，单程cn2美国服务器，hybla降到80K，bbr降到10K，cubic降到4K，在tcp全体投降的状态下，妹子依然8M，比hybla快100倍，比bbr快800倍，比cubic快2000倍。

## 安装

分别在两端装：

```bash
gem install girl
```

家用近端通常是内网的一台电脑，或者虚拟机、路由器，远端是海外服务器。

任意可以连网的设备，把网关和dns设成近端ip（有线），或者连上近端wifi（无线），起飞。

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

满足：特定域名+53端口，dns查询包将被丢弃，到不了远端。办法是加密，或者换个端口。

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

和上面一样可以覆盖加解密方法。不同的是，这里加解密只作用于第一段流量。为什么是第一段？ssh的第一段流量是明文版本号，https的第一段流量含明文域名。后面本来就是乱码。

## 3. 树莓派

还抱着openwrt不放，破解闭源的路由器，为停产的机器写兼容补丁并标注各种freeze issue？你可真是个怀旧的人了。

没有必要了。树莓派了解一哈，便宜，高配，小身材，自带wifi，开源，完全有资格替代传统路由器，只要求一点点的diy。

妹子配树莓派是绝配。

![妹子路由器1](http://89.208.243.143/pic1.jpg)

![妹子路由器3](http://89.208.243.143/pic3.jpg)
