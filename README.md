# girl

妹子，满足上网需求。

## 变快

访问海外，很慢：

```
本机 <----- 慢（50K/s） ----- 目的地
```

中转一下（先下载到vps，再下载到本地），快了：

```
本机 <----- 快（10M/s） ----- vps <- 目的地
```

进一步，改为自动中转：

```
流量 -> 代理 ----- 快（10M/s） -----> vps（代理服务端） -> 目的地
```

体现在游戏上，读条和转圈变快。

体现在下载上，下载速度从几K，几十K，变成几兆，几十兆。

再进一步，多加一个点，两点组成一根通道：

```
流量 -> 代理 -> 本机/路由器（近端） ----- 快（10M/s） -----> vps（远端）-> 目的地
```

通道的好处是，可以在近端区分国内外，国内直连，海外走通道。

第二，可以在流量出门前改变它，以回避邪恶。

借助一个域名列表，和一个ip段列表，完整的路线图：

```
流量 -> 代理 -> 妹子近端 -> 域名命中remotes.txt？-- hit ----------> 远端 -> 解析域名 -> 目的地
                                              \
                                               `- not hit -> 解析域名 -> ip命中directs.txt？-- hit -----> 目的地
                                                                                          \
                                                                                           `- not hit -----> 远端 -> 目的地
```

## 使用

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

```bash
ruby proxyd.rb
```

近端，可以是本机，树莓派，内网服务器，路由器：

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
    "redir_port": 6666,                 // 近端（本地）端口
    "proxyd_host": "1.2.3.4",           // 远端服务器
    "proxyd_port": 6060,                // 远端端口
    "infod_port": 6070,                 // 查询服务，供远端本机调用
    "direct_path": "girl.direct.txt",   // 直连ip段
    "remote_path": "girl.remote.txt",   // 交给远端解析（并中转流量）的域名列表
    "nameserver": "114.114.114.114",    // 域名列表之外的域名就近查询，国内的dns服务器
    "im": "girl",                       // 标识，用来识别近端
    "resolv_port": 1053,                // 透明中转，近端接收dns查询流量的端口
    "resolvd_port": 5353,               // 透明中转，远端dns查询中继端口
    "relay_port": 1066,                 // 透明中转，近端接收tcp流量的端口
    "mirrord_port": 7070,               // 镜子服务端口
    "mirrord_infod_port": 7080,         // 镜子服务查询端口，供本地调用
    "p2d_ports": [ [ "girl", 2222 ] ],  // 镜子服务，标识对应影子端口
    "p2d_host": "127.0.0.1",            // 镜子服务，影子端口暴露地址，0.0.0.0为对外
    "appd_host": "127.0.0.1",           // 镜子p1端，内网应用地址
    "appd_port": 22                     // 镜子p1端，应用端口
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

下载一个海外资源，比较一下速度：

直连：

```bash
curl --verbose -x '' -O https://fra-de-ping.vultr.com/vultr.com.100MB.bin
```

走妹子：

```bash
curl --verbose -x http://127.0.0.1:6666 -O https://fra-de-ping.vultr.com/vultr.com.100MB.bin
```

或者：

```bash
curl --verbose -x socks5h://127.0.0.1:6666 -O https://fra-de-ping.vultr.com/vultr.com.100MB.bin
```

妹子同时支持http和socks5代理。

## 回避邪恶

邪恶使得：

1. dns查询得到错误的ip
2. tcp流量无法到达特定ip

1和2，解法是中转。但是，中转仍将碰见邪恶：

3. 若流量含有特定域名，且形似http头或者证书，会吃到一个reset

例如：

```text
CONNECT google.com HTTP/1.1\r\n\r\n
```

4. 回程流量引起，ping不通vps，3分钟后恢复

3和4，解法是混淆流量。

还没结束：

5. 一旦目的地（远端）ip被收集，任何tcp建立连接后，来源（近端）端口被封，后续流量无法到达
6. 一旦目的地（远端）ip被收集，任何udp第一段流量后，来源（近端）端口被封，后续流量无法到达
7. udp和tcp分开触发，被偷偷限速在200K，重启vps恢复

梳理一遍解法：

1. 中转
2. 中转
3. 混淆域名（可以自定义）
4. 混淆流量（可以自定义）
5. 不停的向vps建https连接或者socks5连接（包括shadowsocks）即可提高被收集几率。而不使用这两个协议，则没发现被收集的情况。
6. udp则不看任何流量内容，直接被收集，流量越频繁被收集几率越高，因此，不心跳，降低频率，每发一个udp就换一个新端口。
7. 气死

以上就是妹子。

## docker

快速体验可以使用我发布在docker hub的妹子镜像。

远端一键启动：

```bash
docker run -d --restart=always -e USE=proxyd --network=host -it takafan/girl
```

近端一键启动：

```bash
docker run -d --restart=always -e USE=proxy -e PROXYD_HOST=1.2.3.4 -p6666:6666 -it takafan/girl
```

## 设备端

不用装任何东西，直接填代理，系统自带的代理。

windows: 开始 > 设置 > 网络和Internet > 代理 > 手动设置代理 > 使用代理服务器 > 开 > 填近端的地址和端口 > 保存

macos: 系统偏好设置 > 网络 > 选中一个连接 > 高级 > 代理 > 打勾SOCKS代理 > 填近端的地址和端口 > 好 > 应用

ios: 设置 > 无线局域网 > wifi详情 > 配置代理 > 手动 > 填近端的地址和端口 > 存储

android: 设置 > WLAN > 长按一个连接 > 修改网络 > 显示高级选项 > 代理 > 手动 > 填近端的地址和端口 > 保存

ps4: 设定 > 网路 > 设定网际网路连线 > 使用Wi-Fi/使用LAN连接线 > 自订 > 选择一个连接 > 一路默认到Proxy伺服器 > 使用 > 填近端的地址和端口 > 继续

switch: 设置 > 互联网 > 互联网设置 > 选择一个连接 > 更改设置 > 代理服务器设置 > 启用 > 填近端的地址和端口 > 保存

## 代理之外

代理设在那里，但应用程序可以选择不走。例如switch版的youtube。

妹子支持透明中转，可以借助iptables把dns查询和全部tcp流量引给妹子。

远端，多启一个dns查询中继：

```ruby
# resolvd.rb
require 'girl/resolvd'

Girl::Resolvd.new '/etc/girl.conf.json'
```

```bash
ruby resolvd.rb
```

近端：

```ruby
# relay.rb
require 'girl/relay'

Girl::Relay.new '/boot/girl.conf.json'
```

```bash
ruby relay.rb
```

iptables配置：

```bash
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 1053
iptables -t nat -A PREROUTING -d 127.0.0.1 -j RETURN
iptables -t nat -A PREROUTING -d 192.168.1.59 -j RETURN
iptables -t nat -A PREROUTING -d 192.168.59.1 -j RETURN
iptables -t nat -A PREROUTING -p tcp -d 1.2.3.4 --match multiport --dports 80,443 -j REDIRECT --to-ports 1066
iptables -t nat -A PREROUTING -p tcp -d 1.2.3.4 -j RETURN
iptables -t nat -A PREROUTING -p tcp -j REDIRECT --to-ports 1066
```

连近端wifi，打开youtube。

## 连回家

反过来，妹子支持从外面连进家。

```
          mirrord
         ^       ^
        ^         ^
      p1           ssh
     ^
    ^
sshd
```

不单sshd，可以是p1所在内网的任意应用。

镜子端：

```ruby
# mirrord.rb
require 'girl/mirrord'

Girl::Mirrord.new '/etc/girl.conf.json'
```

```bash
ruby mirrord.rb
```

p1端：

```ruby
# p1.rb
require 'girl/p1'

Girl::P1.new '/boot/girl.conf.json'
```

```bash
ruby p1.rb
```

镜子端本地，ssh连p1映射出来的影子端口：

```bash
ssh -p2222 pi@localhost
```

## udp漫谈

有没有办法，降低联机游戏的延迟？

先来看看，联机是怎么实现的，用udp实现联机，有3种做法：

1. 影子同步
2. 服务端同步
3. 房主同步

画面：

1. 影子同步：你先动，别人屏幕里的你再动。
2. 服务端同步：（按键会多出几十毫秒的延迟）同时动，所有人的屏幕一样。严格的讲，离服务器近的人，会先看到最新的画面，但只要不超过2帧，对凡人没区别。
3. 房主同步：同时动。房主没有延迟，略有优势。

玩家间有互动的游戏，需要保证一根时间轴，只会是2或3。
对于2，走一条短且通畅的线路中转，勉强可以降低延迟，但降低不到（你到vps的ping值+vps到游戏服务器的ping值）以下。
对于3，3是不经服务端广播，直接p2p，中转只会增加延迟。

所以我倾向于搬家。
