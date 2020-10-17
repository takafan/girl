# girl

妹子，高速通道。

访问海外资源，往往很慢：

```
本机 <----- 50K/s ----- 目的地
```

中转一下，可以快很多：

```
本机 <----- 10M/s ----- vps <- 目的地
```

直接下下不动，那么先下载到vps，再从vps下载到本地。根据线路不同，拥控算法不同，速度能有1M甚至10M。

进一步，改为自动中转：

```
流量 -> 代理 ----- 10M/s -----> vps（代理服务端） -> 目的地
```

自动了。

还有个事，邪恶的存在。

妹子来了，和传统代理稍不同，妹子是一根通道：

```
流量 -> 代理 -> 本机/路由器（妹子近端） ----- 10M/s -----> vps（妹子远端）-> 目的地
```

通道的好处是，可以在流量出门前改动它，以回避邪恶。

直连还是走通道是可以控制的，借助一个域名列表，和一个ip段列表。完整的路线图：

```
流量 -> 代理 -> 妹子近端 -> 域名命中remotes.txt？-- hit ----------> 远端 -> 解析域名 -> 目的地
                                              \
                                               `- not hit -> 解析域名 -> ip命中directs.txt？-- hit -----> 目的地
                                                                                          \
                                                                                           `- not hit -----> 远端 -> 目的地
```

起飞。

## udp怎么办

udp是另一个世界。可以不看。

中转让tcp变快。也能让udp变快吗？

udp的快，是指：低延迟。从家到代理服务器的ping值，加上代理服务器到目的地的ping值，小于直连，代理才有意义。为了追求低延迟，udp很需要区分国内外。目的地在国外，可以给它找条更短的线路，目的地在国内，直连就是最快的。

但udp不能区分国内外。因为p2p的存在。要是把国内ip段设为直连，采用p2p联机的游戏会怎么样：游戏匹配服务器在海外，匹配到国内玩家，他从他洞里出来穿你（映射到远端的）洞，通。你却不走打好的洞突然直连穿他，不通。因此：要么不走，要么统统走。

并且，现实中，udp代理是不存在的。首先，http代理不支持udp，也就是说，ios，android，ps4，switch，不支持。然后，windows和macos可设socks5，socks5支持udp。但走不走代理，还是由应用程序实现，实现socks5，有，实现socks5中的UDP ASSOCIATE部分，没见过。所以，socks5支持udp，但形同虚设。

只剩下vpn能使得与国外玩家联机变快。但要是匹配到国内玩家，反而变慢了。

提高p2p联机质量的正确姿势其实是厂商开多个匹配服务器，亚洲玩家全去同一个服务器，直连。

## 使用篇

分别在两端装：

```bash
apt install ruby
gem install girl
```

远端，通常是vps：

```ruby
# proxyd.rb
require 'girl/proxyd'

Girl::Proxyd.new '/etc/girl.conf.json'
```

近端，可以是本机，树莓派，内网服务器，路由器：

```ruby
# proxy.rb
require 'girl/proxy'

Girl::Proxy.new '/boot/girl.conf.json'
```

girl.conf.json的格式：

```javascript
// girl.conf.json
{
    "proxy_port": 6666,                   // 代理服务，近端（本地）端口
    "proxyd_host": "1.2.3.4",             // 代理服务，远端服务器
    "proxyd_port": 6060,                  // 代理服务，远端端口
    "infod_port": 6070,                   // 查询服务，供远端本机调用
    "direct_path": "girl.direct.txt",     // 直连ip段
    "remote_path": "girl.remote.txt",     // 交给远端解析的域名列表
    "im": "girl",                         // 标识，用来识别近端
    "worker_count": 4                     // 子进程数，默认取cpu个数
}
```

获取注册在亚太的CN的ip段：

```bash
curl -O http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest
cat delegated-apnic-latest | grep ipv4 | grep CN | awk -F\| '{ printf("%s/%d\n", $4, 32-log($5)/log(2)) }' > girl.direct.txt
cat delegated-apnic-latest | grep ipv6 | grep CN | awk -F\| '{ printf("%s/%d\n", $4, $5) }' >> girl.direct.txt
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

很多网站流行把静态资源放到额外的一个域名下，需要自行f12探索一下。

不写的话，本地解析google.com会得到假ip，但只要假ip取值取在国内ip段之外，还是会走远端重新解析。

## 应对邪恶

实际是解决2个问题：

1. dns查询得到正确的ip。
2. tcp流量正常的到达目的地。

办法正是中转。

用udp来中转，udp邪恶没管，无需改动流量。但udp存在被限速。一时间的流量，200K之后的会丢失。

回避限速需要故意停顿，发200K，停顿50毫秒发第二个200K，这样仍可以达到几兆的速度，但比不了没被限速的tcp。

tcp也存在同样的被限速，但仅是我遇到的个例：电信被限，移动正常，一台服务器被限，隔壁机房正常，几个月后恢复。

用tcp来中转，流量会如实的到达远端，但若流量含有特定域名，且形似http头或者证书，近端会先吃到一个reset。来自邪恶。

例如：

```text
CONNECT google.com HTTP/1.1\r\n\r\n
```

妹子提供开放式的加解密。覆盖下面两个方法即可：

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
ALT = { '.' => '^', '^' => '.', 'g' => 'o', 'o' => 'g' }

def encode( data )
  data.gsub( /\.|\^|g|o/ ){ | c | ALT[ c ] }
end

def decode( data )
  data.gsub( /\.|\^|g|o/ ){ | c | ALT[ c ] }
end
```

把点转了，等于混淆了所有域名。域名是https唯一的漏洞。

而对于明文的http，转掉点不一定够，仍然可能吃到3分钟阻断，例如chrome后台程序产生的明文流量。对换g和o，用于避免chrome引发阻断。

完整例子：

远端：

```ruby
# proxyd.rb
require 'girl/proxyd'

module Girl
  module Custom
    ALT = { '.' => '^', '^' => '.', 'g' => 'o', 'o' => 'g' }

    def encode( data )
      confuse( data )
    end

    def decode( data )
      confuse( data )
    end

    def confuse( data )
      data.gsub( /\.|\^|g|o/ ){ | c | ALT[ c ] }
    end
  end
end

Girl::Proxyd.new '/etc/girl.conf.json'
```

```bash
ruby proxyd.rb
```

近端：

```ruby
# proxy.rb
require 'girl/proxy'

module Girl
  module Custom
    ALT = { '.' => '^', '^' => '.', 'g' => 'o', 'o' => 'g' }

    def encode( data )
      confuse( data )
    end

    def decode( data )
      confuse( data )
    end

    def confuse( data )
      data.gsub( /\.|\^|g|o/ ){ | c | ALT[ c ] }
    end
  end
end

Girl::Proxy.new '/boot/girl.conf.json'
```

```bash
ruby proxy.rb
```

启好了，测试一下：

```bash
curl -x http://127.0.0.1:6666 https://www.google.com/
curl -x socks5h://127.0.0.1:6666 https://www.google.com/
```

妹子同时支持http和socks5代理。

## docker

快速体验可以直接使用我发布在docker hub的妹子镜像。

远端一键启动：

```bash
docker run -d --restart=always -e USE=proxyd --network=host -it takafan/girl
```

近端一键启动：

```bash
docker run -d --restart=always -e USE=proxy -e PROXYD_HOST=1.2.3.4 -p6666:6666 -it takafan/girl
```

## mac版docker，cpu爆满bug

bug细节，可以不看：容器里，当妹子近端发起向目的地的连接，docker会查看当前网络，如果当前网络勾了https代理，会生成一段针对目的地的CONNECT，改为请求代理地址，于是妹子又得到一个CONNECT，我连我自己，无限连，cpu爆满。

不勾https代理，避免bug。

不勾的话chrome有问题，好在有兼顾chrome的设法：只勾socks代理。

dropbox又有问题，自动检测不灵了，好在dropbox支持设手动。

## 设备端

远端近端启好后，在想用的设备上设代理，填近端的地址。

不论windows，mac，手机，游戏机，代理功能都有自带。

windows: 开始 > 设置 > 网络和Internet > 代理 > 手动设置代理 > 使用代理服务器 > 开 > 填写地址和端口 > 保存

macos: 系统偏好设置 > 网络 > 选中一个连接 > 高级 > 代理 > 打勾SOCKS代理 > 填写地址和端口 > 好 > 应用

ios: 设置 > 无线局域网 > wifi详情 > 配置代理 > 手动 > 填写服务器和端口 > 存储

android: 设置 > WLAN > wifi详情 > 代理 > 手动 > 填写主机名和端口 > 保存

ps4: 设定 > 网路 > 设定网际网路连线 > 使用Wi-Fi/使用LAN连接线 > 自订 > 选择一个连接 > 一路默认到Proxy伺服器 > 使用 > 填写位址和Port码 > 继续

switch: 设置 > 互联网 > 互联网设置 > 选择一个连接 > 更改设置 > 代理服务器设置 > 启用 > 填写地址和端口 > 保存

## ipv6

妹子支持ipv6，优先走ipv6。如果近端所在的操作系统打开了ipv6，可以获取到ipv6地址，也可以dns解析到目的地的ipv6地址，还不够，需要连的通。

简单的测法，连光猫wifi，访问test-ipv6.com，看通不通。

如果不通，需关闭近端系统上的ipv6。

windows: 开始 > 设置 > 网络和Internet > 以太网 > 更改适配器选项 > 右键属性 > 取消勾选Internet协议版本6（TCP/IPv6）

macos:

```bash
networksetup -setv6off Ethernet
networksetup -setv6off Wi-Fi
```

linux:

```bash
echo -e 'net.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1' > /etc/sysctl.d/59-disable-ipv6.conf
sysctl --system
```
