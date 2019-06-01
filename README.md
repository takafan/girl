# girl - while network is evil, here's a patch.

妹子解决2个问题：

1. dns查询得到正确的ip。
2. tcp流量正常的到达目的地。

妹子分成近端和远端，近端可以是内网的一台电脑，或者虚拟机、路由器。远端是海外服务器。通常：

```
近端 ---------------> 目的地
```

另一个目的地，它可能“不通”，或者路上不安全，或者慢。于是需要第二根线：

```
近端 ---------------> 目的地1
    \                     
     `---- 远端 ----> 目的地2
```

第二根线，流量由近端发给远端，再由远端发给目的地。其中，近端发给远端的那一段，tcp流量被打包成udp，在应用层实现可靠，好处是比tcp快，有加速效果。

任意可以连网的设备，把网关和dns设成近端ip（有线），或者连上近端wifi（无线），起飞。

安装：

```bash
gem install girl
```

## 1. dns查询得到正确的ip

```
    dns query -> resolv ---- default -------------------> 114.114.114.114
                   ,    \                     
               cache     `-- hit list --> encode --> resolvd ---> 8.8.8.8
```

远端：

```ruby
require 'girl/resolvd'

Girl::Resolvd.new( 7070 ).looping
```

近端：

```ruby
require 'girl/resolv'

Girl::Resolv.new( 1717, [ '114.114.114.114' ], '{ your.server.ip }', 7070, [ 'google.com' ] ).looping
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

Girl::Tun.new( '{ your.server.ip }', 9090, 1919 ).looping
```

```bash
dig +short www.google.com @127.0.0.1 -p1717 # got 216.58.217.196

iptables -t nat -A OUTPUT -p tcp -d 216.58.217.196 -j REDIRECT --to-ports 1919

curl https://www.google.com/
```

## 3. 速度

在掉包的环境下，比如国际线路，传输速度取决于重传。tcp的重传写在拥控算法里，问题是，不快。

妹子为了快：

1. 一秒重传。
2. 自动扩展至文件系统的写前缓存。例如下载一个5个G的游戏，由于远端下载游戏要比传给近端快，游戏会先被分块存成文件存在远端。
3. 写前发出变成写后，对面收到即发确认包来抵消，跳号包放碎片缓存。

结果是，下载美国服务器上的文件，妹子比流行的拥控算法bbr/hybla快3倍，比默认的cubic快6倍。

3倍6倍是基于电信新线路gia。老线路，单程cn2，晚上下载速度不足10k，在tcp几乎不可用的情况下，妹子依然2M，差距拉开到200倍。

## 4. 树莓派

还抱着openwrt不放，破解闭源的路由器，为停产的机器写兼容补丁并标注各种freeze issue，你可真是个怀旧的人了。

没有必要了。树莓派了解一哈！便宜却高配，小身材，自带wifi，开源，完全有资格替代传统路由器，只要求一点点的diy。

妹子配树莓派是绝配。

![妹子路由器1](http://89.208.243.143/pic1.jpg)

![妹子路由器3](http://89.208.243.143/pic3.jpg)

## 网关管理界面

```bash
yarn build
```

![妹子路由器9](http://89.208.243.143/pic9.png)

## 服务器推荐

ping值稳定：cn2 gia。低延迟：中华电信、韩国电信。
