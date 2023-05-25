# girl

```
流量 -> 代理 ---!---> vps -> 目的地
```

代理，不论http，https，socks5，shadowsocks，会受到邪恶阻拦。

妹子，回避邪恶。

## 邪恶细节

1. dns查询得到错误的ip。
2. tcp流量无法到达特定ip。
3. 出国udp，流量稍微多一点，来源ip被封，ping不通vps，3分钟后恢复。
4. 出国tcp，若为代理协议，且含有特定域名，会吃到一个reset。例如：`CONNECT google.com HTTP/1.1\r\n\r\n`
5. tcp阻断，触发后，来源ip每和vps建立tcp连接，不论端口，来回两次流量即被封来源端口，后续流量无法到达，但ping的通，udp可达，企业宽带极易触发。
6. 用shadowsocks稍微频繁一点，国内任何来源的tcp及icmp均无法到达vps，但udp可达，持续几天至几个月不等。

* 应对1和2，须依靠中转：

```
流量 -> 代理 -> 本机/路由器 ------> vps -> 目的地
```

* 中转会遇到3-6。
* 应对3：几乎不能走udp。
* 应对4：自定义协议。
* 应对5：三种方案：

```
流量 ------> vps（非知名供应商ip段） -> 目的地
```

```
流量 ------> 海外cdn中转 ------> vps -> 目的地
```

```
流量 ------> 国内专线/vps ------> 海外vps -> 目的地
```

妹子支持第三种。

完整的路线图：

```
流量 -> 代理 -> 妹子近端 -> 域名命中remotes.txt？-- hit ----- 中继（应对6） -----> 远端 -> 解析域名 -> 目的地
                                              \
                                               `- not hit -> 解析域名 -> ip命中directs.txt？-- hit -----> 目的地
                                                                                          \
                                                                                           `- not hit -----> 远端 -> 目的地
```

## 使用

### 远端，通常是vps：

1. 安装ruby，妹子：

```bash
apt install ruby
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
  "girl_port": 8080    // 妹子端口，防重放
}
```

### 近端，可以是本机，树莓派，内网服务器，路由器:

1. 以windows为例，下载和安装ruby：https://rubyinstaller.org/

2. 安装妹子：

```bash
gem install girl
```

3. 创建 proxy.run.rb：

```ruby
require 'girl/proxy'

Girl::Proxy.new '/etc/proxy.conf.json'
```

4. 启动近端：

```bash
ruby proxy.run.rb
```

5. proxy.conf.json 样例：

```javascript
{
  "redir_port": 6666,                           // 近端（本地）端口
  "proxyd_host": "1.2.3.4",                     // 远端服务器
  "proxyd_port": 6060,                          // 远端端口
  "girl_port": 8080,                            // 妹子端口，防重放
  "direct_path": "C:/girl.win/girl.direct.txt", // 直连ip段
  "remote_path": "C:/girl.win/girl.remote.txt", // 交给远端解析的域名列表
  "im": "taka-pc"                               // 设备标识
}
```

6. 获取注册在亚太的CN的ip段：

```bash
curl -O http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest
cat delegated-apnic-latest | grep ipv4 | grep CN | awk -F\| '{ printf("%s/%d\n", $4, 32-log($5)/log(2)) }' > girl.direct.txt
cat delegated-apnic-latest | grep ipv6 | grep CN | awk -F\| '{ printf("%s/%d\n", $4, $5) }' >> girl.direct.txt
```

7. girl.remote.txt的格式：

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

## 中继，通常是国内专线/vps：

1. 创建 relay.run.rb：

```ruby
require 'girl/relay'

Girl::Relay.new '/etc/relay.conf.json'
```

2. 启动中继：

```bash
ruby relay.run.rb
```

3. relay.conf.json 样例：

```javascript
{
  "relay_proxyd_port": 5060, // 中继远端端口
  "relay_girl_port": 5080,   // 中继妹子端口
  "proxyd_host": "1.2.3.4",  // 远端服务器
  "proxyd_port": 6060,       // 远端端口
  "girl_port": 8080          // 妹子端口
}
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

妹子支持从外面连进内网。

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

1. 镜子端：

```ruby
# mirrord.run.rb
require 'girl/mirrord'

Girl::Mirrord.new '/etc/mirrord.conf.json'
```

```bash
ruby mirrord.run.rb
```

2. mirrord.conf.json 样例：

```javascript
{
  "mirrord_port": 7070,       // 镜子服务端口
  "im_infos": [               // 映射列表
    { 
      "im": "taka-pi",        // 标识
      "p2d_port": 2222,       // p2影子端口
      "p1d_port": 0           // p1影子端口，0为随机
    }
  ]
}
```

3. p1端：

```ruby
# p1.run.rb
require 'girl/p1'

Girl::P1.new '/etc/p1.conf.json'
```

```bash
ruby p1.run.rb
```

4. p1.conf.json 样例：

```javascript
{
    "proxyd_host": "1.2.3.4", // 镜子服务器
    "mirrord_port": 7070,     // 镜子端口
    "appd_host": "127.0.0.1", // 镜子p1端，内网应用地址
    "appd_port": 22,          // 镜子p1端，应用端口
    "im": "taka-pi"           // 设备标识
}
```

5. 镜子端本地，ssh连p2影子端口：

```bash
ssh -p2222 pi@localhost
```
