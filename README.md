# girl

while network is evil, here's a patch.

妹子解决4个问题：

1. dns查询得到正确的ip。
2. tcp流量正常的到达目的地。
3. 在掉包的环境下保持速度。
4. 处于nat里的客户端，与处于另一个nat里的服务端p2p。

```bash
gem install girl
```

## 1. dns查询得到正确的ip

```
    dns query -> resolv ---- default -----------------> 114.114.114.114
                   ,    \                     
               cache     `-- hit list --> swap --> resolvd ---> 8.8.8.8
```

server:

```ruby
require 'girl/resolvd'

Girl::Resolvd.new( 7070 ).looping
```

home:

```ruby
require 'girl/resolv'

Girl::Resolv.new( 1717, [ '114.114.114.114' ], '{ your.server.ip }', 7070, [ 'google.com' ] ).looping
```

```bash
dig google.com @127.0.0.1 -p1818
```

往往第一段流量，就能看出你要干嘛。比如dns查询的第一段，可以看出它是dns查询，以及你要解析哪个域名。比如ssh的第一段，可以看到它是ssh，和它的版本号。比如https的第一段，一团乱码之中，夹着一个你要去的域名。

想混淆第一段流量，就覆盖swap方法：

```ruby
def swap( data )
  # overwrite me, you'll be free
  data
end
```

## 2. tcp流量正常的到达目的地

```
    tcp traffic -> iptables ---- cn ip -----------------------------> 微博
                            \                        
                             `-- not cn --> tun --> swap --> tund --> 谷歌
                                                              ,
                                                          cache
```

server:

```ruby
require 'girl/tund'

Girl::Tund.new( 9090 ).looping
```

home:

```ruby
require 'girl/tun'

Girl::Tun.new( '{ your.server.ip }', 9090, 1919 ).looping
```

```bash
dig +short www.google.com @127.0.0.1 -p1818 # got 216.58.217.196

iptables -t nat -A OUTPUT -p tcp -d 216.58.217.196 -j REDIRECT --to-ports 1919

curl https://www.google.com/
```

## 3. 速度

在掉包的环境下，比如国际线路，传输速度取决于重传。tcp的重传写在拥控算法里，问题是，不快。

妹子为了快：

1. 一秒后重传。
2. 自动扩展至文件系统的写前缓存。例如下载一个5个G的游戏，由于远端下载游戏要比传给近端快，游戏会先被分块存成文件存在远端。
3. 写前发出变成写后，对面收到即发确认包来抵消，跳号包放碎片缓存。
4. 再看tcp，有限的内存迫使它发明窗口，窗口满了就不得不清空，跳号包被清了对面就需要把已送达的这个包再传一遍，甚至为了不让窗口满，发明了协商降速。

结果是，下载美国服务器上的文件，妹子比流行的拥控算法bbr/hybla快3倍，比默认的cubic快6倍。

3倍6倍是基于电信新线路gia。老线路，单程cn2，晚上下载速度不足10k，在tcp几乎不可用的情况下，妹子依然2M，差距拉开到200倍。

## 4. p2p

访问家里的电脑，需要把电脑上的sshd暴露到外网。暴露到外网，需要端口映射。光猫自带miniupnpd，允许你用upnpc映射一个端口到光猫上。可惜的是，这个映射很容易消失，你也没办法打补丁。

有个彻底的办法：改桥接。自己的机器，自己拨号，自己面向外网，自己建nat，这才是internet！

复杂的来了。如果你的套餐还包含高清iptv，高清iptv需要获取内网ip，需要获取外网ip。它写死了，你不得不兼容它。第一步，为它分配内网ip的时候要传特殊的dhcp-option。第二步，带它去vlan85领外网ip。然后就能看了。

厌倦了hack，也可以不依赖光猫。准备一个外网服务器，充当镜子，把服务映射到镜子上，客户端访问镜子。

但镜子需要额外产生一份流量在服务器身上，上下行速度取决于服务器的远近和带宽。所以，如果是ssh、sftp、远程桌面，p2p更加合适。

由于两头都在nat里，听，是听不到的，必须两头同时发起连接。因此需要一台配对服务器p2pd传递双方地址。剩下就是两个头之间的事了，一头p2p1代理sshd，另一头p2p2代理ssh，从各自的洞里出来直连对面。

```
                p2pd                           p2pd
                ^                              ^
               ^                              ^
    sshd <- p2p1                            p2p2 <- ssh
               \                            ,          
                `swap -> nat <-> nat <- swap
```

server:

```ruby
require 'girl/p2pd'

Girl::P2pd.new( 6262, '/tmp/p2pd' ).looping
```

p1:

```ruby
require 'girl/p2p1'

Girl::P2p1.new( '{ your.server.ip }', 6262, '127.0.0.1', 22, 1800, '周立波' ).looping
```

p2:

```bash
echo "ls -lt /tmp/p2pd" | sftp -q root@{ your.server.ip } # saw 6.6.6.6:12345-周立波
```

```ruby
require 'girl/p2p2'

Girl::P2p2.new( '{ your.server.ip }', 6262, '6.6.6.6:12345-周立波', '/tmp/p2p2' ).looping
```

```bash
ls -lt /tmp/p2p2 # saw 45678--6.6.6.6:12345-周立波

ssh -p45678 libo@127.0.0.1
```

## 5. 妹子路由器

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

ping值稳定：cn2 gia。低延迟：中华电信、韩国电信。或者找我“买”一台妹子路由器，就不用管服务器了，同时也是支持我。

任何可以连网的设备，把网关和dns设成妹子，或是连上妹子wifi，起飞。

1000一台，寄到家。邮件咨询： qqtakafan@gmail.com
