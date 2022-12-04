# girl

```
流量 -> 代理 ---!---> vps -> 目的地
```

代理，不论http，https，socks5，shadowsocks，会受到邪恶阻拦。

```
流量 -> 代理 -> 本机/路由器（自定义传输） ------> vps -> 目的地
```

自定义传输，回避邪恶。

## 邪恶细节

1. dns查询得到错误的ip。
2. tcp流量无法到达特定ip。
3. 出国tcp，若为代理协议，且含有特定域名，会吃到一个reset。例如：`CONNECT google.com HTTP/1.1\r\n\r\n`
4. 出国udp，流量稍微多一点，来源ip被封，ping不通vps，3分钟后恢复。
5. 出国tcp，若为代理协议或者tls握手，后续流量稍微多一点，来源端口被封，后续流量无法到达。
6. 出国tcp，流量稍微频繁一点，来源ip去往vps的tcp被拒，不论目标端口，但ping的通，udp可达，几分钟后恢复，容易反复触发，流量越随机越容易触发。
7. 用shadowsocks稍微频繁一点，国内任何来源的tcp及icmp均无法到达vps，但udp可达，持续几天至几个月不等。

回避1和2须依靠中转，但中转会遇到3-7，妹子是针对3-7的极简解。

8. udp，tcp分开触发，被偷偷限速在200K，重启vps恢复。

## 完整的路线图

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
    "girl_port": 8080,                  // 妹子端口，防重放
    "direct_path": "girl.direct.txt",   // 直连ip段
    "remote_path": "girl.remote.txt",   // 交给远端解析（并中转流量）的域名列表
    "nameserver": "114.114.114.114",    // 域名列表之外的域名就近查询，国内的dns服务器
    "im": "taka-pc",                    // 设备标识
    "ims": [ "taka-pc", "taka-mac" ],   // 远端允许的设备列表
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
