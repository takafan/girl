# girl

```txt
流量 -> 代理 ---!---> vps -> 目的地
```

代理，不论http，https，socks5，shadowsocks，会受到邪恶阻拦。

妹子，回避邪恶。

```txt
流量 -> 代理 -> 妹子近端 -> 域名命中proxy.remote.txt？-- hit --> 远端 -> 解析域名 -> 目的地
                      \
                       `- no -> 解析域名 -> ip命中proxy.direct.txt？-- hit --> 目的地
                                                                 \
                                                                  `- no -> 远端 -> 目的地
```

## 使用

### 远端

通常是海外vps。

1. 安装ruby，妹子：

```bash
dnf install ruby
gem install girl
```

2. 创建 proxyd.run.rb：

```ruby
require 'girl/proxyd'

Girl::Proxyd.new '/etc/proxyd.conf.json'
```

3. 启动远端：

```bash
ruby proxyd.run.rb
```

4. proxyd.conf.json 样例：

```javascript
{
    "proxyd_port": 6060, // 远端端口
    "ims": [ "taka-pc" ] // 允许的近端标识
}
```

### 近端

可以是本机，内网服务器，路由器，各种派。

1. 安装ruby：

windows：

访问 https://rubyinstaller.org/ 或者 https://rubyinstaller.cn/ 下载和安装ruby

openwrt: 

```bash
opkg update
opkg install ruby ruby-gems ruby-did-you-mean ruby-enc-extra ruby-rdoc
```

2. 安装妹子：

```bash
gem sources --add https://gems.ruby-china.com/ --remove https://rubygems.org/
gem install girl
```

3. 创建 proxy.run.rb：

```ruby
#!/usr/bin/env ruby
require 'girl/proxy'

Girl::Proxy.new File.expand_path('../proxy.conf.json', __FILE__)
```

4. 启动近端：

```bash
ruby proxy.run.rb
```

5. proxy.conf.json 样例：

```js
{
    "redir_port": 6666,                          // 代理端口
    "tspd_port": 7777,                           // 网关端口（tcp）/dns端口（udp）
    "proxyd_host": "1.2.3.4",                    // 远端服务器
    "proxyd_port": 6060,                         // 远端端口
    "direct_path": "/boot/proxy.direct.txt",     // 直连ip段
    "remote_path": "/boot/proxy.remote.txt",     // 交给远端解析的域名列表
    "nameserver": "114.114.114.114 192.168.1.1", // 直连dns服务器，多个用空格分隔
    "im": "taka-pc"                              // 近端标识
}
```

6. proxy.direct.txt

```bash
curl -O http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest
cat delegated-apnic-latest | grep ipv4 | grep CN | awk -F\| '{ printf("%s/%d\n", $4, 32-log($5)/log(2)) }' > proxy.direct.txt
cat delegated-apnic-latest | grep ipv6 | grep CN | awk -F\| '{ printf("%s/%d\n", $4, $5) }' >> proxy.direct.txt
```

7. proxy.remote.txt

```txt
google.com
googleusercontent.com
gstatic.com
twimg.com
twitter.com
x.com
youtube.com
ytimg.com
```

不写的话，本地解析google.com会得到假ip，但只要假ip取值取在国内ip段之外，还是会走远端重新解析。

很多网站流行把静态资源放到额外的一个域名下，需要自行f12探索一下。

下载一个海外资源，比较一下速度：

直连：

```bash
curl -x '' -O https://fra-de-ping.vultr.com/vultr.com.100MB.bin
```

走妹子：

```bash
curl -x http://127.0.0.1:6666 -O https://fra-de-ping.vultr.com/vultr.com.100MB.bin
```

或者：

```bash
curl -x socks5h://127.0.0.1:6666 -O https://fra-de-ping.vultr.com/vultr.com.100MB.bin
```

妹子同时支持三种代理：http, http tunnel, socks5。

## 设备端设代理

不用装任何东西，直接填代理，系统自带的代理。

windows: 

```txt
开始 > 设置 > 网络和Internet > 代理 > 手动设置代理 > 使用代理服务器 > 开 > 填近端的地址和端口
添加忽略：192.168.*
勾选请勿将代理服务器用于本地(intranet)地址 > 保存
```

macos: 

```txt
系统偏好设置 > 网络 > 选中一个连接 > 高级 > 代理 > 打勾http和https代理 > 填近端的地址和端口 > 好 > 应用
```

ios: 

```txt
设置 > 无线局域网 > wifi详情 > 配置代理 > 手动 > 填近端的地址和端口 > 存储
```

android: 

```txt
设置 > WLAN > 长按一个连接 > 修改网络 > 显示高级选项 > 代理 > 手动 > 填近端的地址和端口 > 保存
```

ps4: 

```txt
设定 > 网路 > 设定网际网路连线 > 使用Wi-Fi/使用LAN连接线 > 自订 > 选择一个连接 > 一路默认到Proxy伺服器 > 使用 > 填近端的地址和端口 > 继续
```

ns: 

```txt
设置 > 互联网 > 互联网设置 > 选择一个连接 > 更改设置 > 代理服务器设置 > 启用 > 填近端的地址和端口 > 保存
```

steam如果开了着色器预缓存会导致它忽略代理，务必关闭：设置 > 下载 > 启用着色器预缓存 > 关

## dns

有的软件api走代理但cdn采取直连，且该cdn国内dns查询只能得到假ip，例如TikTok app。

妹子近端同时提供dns服务，把该cdn二级域名填在proxy.remote.txt里，妹子会中转给远端查到真ip。

```txt
dns查询 -> 网关 -> 妹子dns端口 -> 命中缓存？- hit -> 返回ip
                            \
                             `- no -> 域名命中proxy.remote.txt？- hit -> 远端解析域名 -> 返回ip
                                                              \
                                                               `- no -> 就近解析域名 -> 返回ip
```

拿openwrt举例，妹子近端启在openwrt系统的派上，openwrt默认由dnsmasq监听53端口，转给妹子的dns端口：`vi /etc/config/dhcp`

```bash
config dnsmasq
    # ...
    option rebind_protection '0'
    option localservice '0'
    option localuse 1
    option noresolv 1
    list server '127.0.0.1#7777'
    list listen_address '127.0.0.1'
    list listen_address '192.168.1.59'
```

```bash
service dnsmasq restart
logread |grep dnsmasq
```

手机里，dns改手动填192.168.1.59（派的内网ip），且只留它一个（避免解析到假ip），TikTok即可正常使用。

## 网关

有的软件会先直连再走代理，可能是为了先验ip，例如Grok app。

还有软件完全无视系统代理，无视环境变量，例如ns上的youtube。

妹子近端同时提供网关服务，可使直连也走妹子，然后区分国内外的去到远端中转。

```txt
流量 -> 网关prerouting -> 妹子网关端口-> ip命中proxy.direct.txt？-- hit ---> 目的地
                                                            \
                                                             `--> 远端 -> 目的地
```

拿openwrt举例，查看是否存在内核模块 nft_chain_nat ：`lsmod | grep nft_chain_nat`

nft把tcp流量转给妹子的网关端口：`vi transparent.conf`

```bash
flush ruleset ip

table ip nat {
    chain prerouting {
        type nat hook prerouting priority dstnat;
        ip daddr {1.2.3.4, 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 255.255.255.255} return
        tcp dport {80, 443} redirect to :7777
    }

    chain postrouting {
        type nat hook postrouting priority srcnat;
        oif eth0 masquerade
    }
}
```

其中 1.2.3.4 为远端ip。

```bash
nft -f transparent.conf
nft list ruleset ip
```

手机/游戏机/pc里，ipv4地址改为手动配置，网关和dns都设为192.168.1.59，Grok app等即可正常使用。

上了伪装的eth0每次收到数据包都需替换其源ip，如果是低配的派做网关，上网网页加载会明显变慢，只推荐有必要的时候配一下，用完去掉：`nft flush ruleset ip`

## 野外

野外手机上网，蜂窝网络环境，openvpn连国内vps是可正常用的，想上外网可搭配妹子。

国内vps里，nft配置和上面一样，把tcp流量转给妹子，同时，dnsmasq监听openvpn服务端ip，把dns查询转给妹子：`vi /etc/dnsmasq.d/girl.conf`

```conf
listen-address=10.8.0.1
no-resolv
server=127.0.0.1#7777
```

openvpn服务端配置添加redirect-gateway，它会要求客户端dns查询一律走vpn：

```conf
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 10.8.0.1"
```
