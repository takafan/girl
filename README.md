# girl

妹子，一根通道，可以操纵流量。

## 变快

访问海外资源，往往很慢：

```
本机 <----- 50K/s ----- 目的地
```

中转一下，可以快很多（先下载到vps，再下载到本地）：

```
本机 <----- 10M/s ----- vps <- 目的地
```

进一步，改为自动中转：

```
流量 -> 代理 ----- 10M/s -----> vps（代理服务端） -> 目的地
```

自动了，体现在游戏上，读条和转圈变快。

体现在下载上，下载速度从几K，几十K，变成几M，几十M。

还没完，妹子来了，传统代理是一个点，妹子多了一个点，两点组成一根通道：

```
流量 -> 代理 -> 本机/路由器（妹子近端） ----- 10M/s -----> vps（妹子远端）-> 目的地
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
    "redir_port": 6666,                   // 近端（本地）端口
    "proxyd_host": "1.2.3.4",             // 远端服务器
    "proxyd_port": 6060,                  // 远端端口
    "infod_port": 6070,                   // 查询服务，供远端本机调用
    "direct_path": "girl.direct.txt",     // 直连ip段
    "remote_path": "girl.remote.txt",     // 交给远端解析（并中转流量）的域名列表
    "im": "girl",                         // 标识，用来识别近端
    "worker_count": 1,                    // 子进程数，默认取cpu个数
    "resolv_port": 1053,                  // 透明中转，近端接收dns查询流量的端口
    "nameserver": "114.114.114.114",      // 透明中转，域名列表之外的域名就近查询，国内的dns服务器
    "resolvd_port": 5353,                 // 透明中转，远端dns查询中继端口
    "relay_port": 1066                    // 透明中转，近端接收tcp流量的端口
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

启好了，测试一下。下载一个海外资源，比较一下速度：

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

实际是解决2个问题：

1. dns查询得到正确的ip。
2. tcp流量正常的到达目的地。

需要靠中转。

用udp来中转，udp始终被运营商限速：一时间的udp流量，200K之后的丢失。

用tcp来中转，需要应对：

1. 若流量含有特定域名，且形似http头或者证书，会吃到一个reset。

例如：

```text
CONNECT google.com HTTP/1.1\r\n\r\n
```

2. 被短暂拦断，ping不通vps，3分钟后恢复。可能由vps回来的流量引起。
3. ssl握手随机被拦。
4. tcp也存在200K限速，但仅是个例。

综合起来就是：流量需要混淆，大流量不走udp，不用ssl。妹子是这些限制下的一个极简解。

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

远端近端启好后，在想用的设备上设代理，填近端的地址。

不论windows，mac，手机，游戏机，代理功能都有自带。

windows: 开始 > 设置 > 网络和Internet > 代理 > 手动设置代理 > 使用代理服务器 > 开 > 填写地址和端口 > 保存

macos: 系统偏好设置 > 网络 > 选中一个连接 > 高级 > 代理 > 打勾SOCKS代理 > 填写地址和端口 > 好 > 应用

ios: 设置 > 无线局域网 > wifi详情 > 配置代理 > 手动 > 填写服务器和端口 > 存储

android: 设置 > WLAN > 长按一个连接 > 修改网络 > 显示高级选项 > 代理 > 手动 > 填写服务器主机名和服务器端口 > 保存

ps4: 设定 > 网路 > 设定网际网路连线 > 使用Wi-Fi/使用LAN连接线 > 自订 > 选择一个连接 > 一路默认到Proxy伺服器 > 使用 > 填写位址和Port码 > 继续

switch: 设置 > 互联网 > 互联网设置 > 选择一个连接 > 更改设置 > 代理服务器设置 > 启用 > 填写地址和端口 > 保存

## ipv6

妹子支持ipv6，优先走ipv6。如果近端所在的操作系统打开了ipv6，先要确保ipv6连的通。

测试连通：连光猫wifi，访问test-ipv6.com，看通不通。如果不通，需关闭近端系统上的ipv6。

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
iptables -t nat -A PREROUTING -i wlan0 -p tcp -j REDIRECT --to-ports 1066
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 1053
```

连近端wifi，打开youtube。
