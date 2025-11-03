# girl

```txt
流量 -> 代理 ---!---> vps -> 目的地
```

代理，不论http，https，socks5，shadowsocks，会受到邪恶阻拦。

妹子，回避邪恶。

## 流转图

```txt
流量 -> 代理 -> 妹子近端 -> 域名命中remotes.txt？-- hit --> 远端 -> 解析域名 -> 目的地
                        \
                            `- no -> 解析域名 -> ip命中directs.txt？-- hit --> 目的地
                                                        \
                                                            `- no -> 远端 -> 目的地
```

## 使用

### 远端

* 通常是海外vps

1. 安装ruby，妹子：

```bash
yum install ruby
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

* 可以是本机，内网服务器，路由器，各种派

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
    "tspd_port": 7777,                           // 网关端口
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
```

7. proxy.remote.txt

```txt
google.com
googleusercontent.com
gstatic.com
twimg.com
twitter.com
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

妹子同时支持三种代理：http, http tunnel, socks5, 以及担当网关和担当dns。

## 设备端设代理

不用装任何东西，直接填代理，系统自带的代理。

windows: 

```txt
开始 > 设置 > 网络和Internet > 代理 > 手动设置代理 > 使用代理服务器 > 开 > 填近端的地址和端口 > 保存
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

## 网关

一些软件无视系统代理，无视环境变量，例如steam，微软商店，ns上的youtube，可以在网关上配置妹子。

```txt
dns查询 -> 网关dnsmasq -> 命中缓存？- hit -> 返回ip
                              \
                               `- no -> 妹子网关端口 -> 域名命中remotes.txt？- hit -> 远端解析域名 -> 返回ip
                                                                             \
                                                                              `- no -> 就近解析域名 -> 返回ip

流量 -> 网关prerouting -> 妹子网关端口-> ip命中directs.txt？-- hit ---> 目的地
                                                        \
                                                         `--> 远端 -> 目的地
```

拿openwrt举例，nft把tcp流量转给妹子的网关端口：

```bash
nft -f transparent.conf
nft list ruleset ip
```

transparent.conf:

```bash
flush ruleset ip

table ip nat {
    chain prerouting {
        type nat hook prerouting priority dstnat;
        ip daddr { 1.2.3.4, 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 255.255.255.255 } return
        tcp dport 1-65535 redirect to :7777
    }

    chain postrouting {
        type nat hook postrouting priority srcnat;
        oif eth0 masquerade
    }
}
```

* 其中 1.2.3.4 为远端ip

开机自动执行：`echo -e 'nft -f /boot/transparent.conf\nexit 0' > /etc/rc.local`

openwrt默认由dnsmasq监听53端口，也转给妹子：`vi /etc/config/dhcp`

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

* pc端网关和dns都设为妹子网关ip即可
* dns只设妹子一个，避免解析到假ip

## 野外

野外手机上网，蜂窝网络环境，openvpn只被允许连国内vps，想上外网可搭配妹子。

国内vps里，nft把tcp流量转给妹子，同时，dnsmasq监听openvpn服务端ip，把dns查询转给妹子：`vi /etc/dnsmasq.d/girl.conf`

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
