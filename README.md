# 妹子

妹子解决4个问题：

1. dns查询得到正确的ip。
2. tcp流量正常的到达目的地。
3. 访问处于nat里的服务。
4. 处于nat里的客户端，与处于另一个nat里的服务端p2p。

4个问题，1个答案：转发。

```bash
gem install girl
```

## 1. 转发dns查询

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

Girl::Resolv.new( 1818, [ '114.114.114.114' ], '{ your.server.ip }', 7070, [ 'google.com' ] ).looping
```

```bash
dig google.com @127.0.0.1 -p1818
```

## 2. 转发tcp流量

```
    tcp traffic -> iptables ---- cn ip ---------------------------------> 微博
                            \                        
                             `-- not cn --> redir --> swap --> relayd --> 谷歌
                                                                ,
                                                            cache
```

一个tcp连接，妹子只混淆其第一段流量，以打乱里面的明文域名。流量只经历一次从内核空间拷贝进应用程序的损耗，所以妹子很快。

server:

```ruby
require 'girl/relayd'

Girl::Relayd.new( 8080 ).looping
```

home:

```ruby
require 'girl/redir'

Girl::Redir.new( 1919, '{ your.server.ip }', 8080 ).looping
```

```bash
dig +short www.google.com @127.0.0.1 -p1818 # got 216.58.217.196

iptables -t nat -A OUTPUT -p tcp -d 216.58.217.196 -j REDIRECT --to-ports 1919

curl https://www.google.com/
```

自定义混淆:

```ruby
module Girl
  class Hex
    def swap( data )
      # overwrite me, you'll be free
      data
    end

    def mix( dst_host, dst_port )
      "#{ dst_host }:#{ dst_port }\n"
    end
  end
end
```

## 3. 访问处于nat里的服务

现在的光猫不单转换信号，还自带拨号，自带一层nat。nat里的服务想暴露到外网，需要端口映射。光猫自带miniupnpd，允许你用upnpc映射一个端口到光猫上。可惜的是，这个映射很容易消失，你也没办法打补丁。

有个彻底的办法：改桥接。自己的机器，自己拨号，自己建nat，服务想装装，想射射，这才是internet！

复杂的来了。如果你的套餐还包含高清iptv，高清iptv需要获取内网ip，需要获取外网ip。它写死了，你不得不兼容它。第一步，为它分配内网ip的时候要传特殊的dhcp-option。第二步，带它去vlan85领外网ip。然后就能看了。成功了？你果然不是普通人。

另一边，妹子，妹子简单，妹子不依赖光猫。但需要准备一个外网服务器，充当镜子，把服务映射到镜子上。客户端访问镜子。

```
                            mirrord <- ssh
                            ,
    sshd <- mirror <- nat <-
```

server:

```ruby
require 'girl/mirrord'

Girl::Mirrord.new( 6060, '127.0.0.1', '/tmp/mirrord' ).looping
```

home:

```ruby
require 'girl/mirror'

Girl::Mirror.new( '{ your.server.ip }', 6060, '127.0.0.1', 22, 1800, '周立波' ).looping
```

server:

```bash
ls -lt /tmp/mirrord # saw 45678-周立波

ssh -p45678 libo@127.0.0.1
```

## 4. p2p

镜子是穿透nat的方案之一，但镜子需要额外产生一份流量在服务器身上，上下行速度取决于服务器的远近和带宽。所以，如果是ssh、sftp、远程桌面，p2p更加合适。还有机会在转发流量前混淆。

由于两头都在nat里，听，是听不到的，必须两头同时发起连接。因此需要一台配对服务器p2pd传递双方地址（打洞）。剩下就是两个头之间的事了，一头p2p1代理sshd，另一头p2p2代理ssh，从各自的洞里出来直连对面。

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

## 5. socks5

自动中转流量靠iptables。如果想手动中转呢？可以用代理。前提是应用支持代理，或者系统支持全局代理。目前最流行的代理是socks5。

```
                                 114.114.114.114
                                 ^
                                ^
    dns query             resolv --> resolvd --> 8.8.8.8
             \            ^
              `-> socks5 ^
                 ^      \                     
    tcp traffic ^        `-> relayd --> destination
```

服务端（192.168.1.59）：

```ruby
require 'girl/socks'

Girl::Socks.new( '0.0.0.0', 1080, '127.0.0.1', 1818, '{ your.server.ip }', 8080 ).looping
```

客户端：

```bash
ALL_PROXY=socks5://192.168.1.59:1080 brew update
```

## 6. 妹子路由器

还抱着openwrt不放，破解闭源的路由器，为停产的机器写兼容补丁并标注各种freeze issue，你可真是个怀旧的人了。

没有必要了。树莓派了解一哈！身材迷你，却高配，自带wifi，开源，紧跟linux当前分支。完全有资格替代传统路由器，只要求一点点的diy。

妹子配树莓派是绝配。把网关和dns设成妹子，或是连上妹子wifi，起飞。

![妹子路由器1](http://89.208.243.143/pic1.jpg)

![妹子路由器3](http://89.208.243.143/pic3.jpg)

## switch连妹子wifi，测速

![妹子路由器5](http://89.208.243.143/pic5.jpg)

![妹子路由器6](http://89.208.243.143/pic6.jpg)

## 油管看5K

![妹子路由器7](http://89.208.243.143/pic7.png)

## 手机看推

![妹子路由器8](http://89.208.243.143/pic8.png)

## 网关管理界面

```bash
yarn build
```

![妹子路由器9](http://89.208.243.143/pic9.png)

## 服务器推荐

晚上不掉包：cn2 gia。低延迟：中华电信、韩国电信。还有一个简单的，稳定的，支持我的选项：找我私下“买”一台妹子——

1000一台，寄到家。邮件咨询： qqtakafan@gmail.com
