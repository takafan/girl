<template>
  <div id="app">
    <el-row>
      <el-col id="header">
        <div><img id="bear" src="./assets/bear.jpg" /></div>
        <div class="right" v-if="is_locked"><i class="el-icon-lock"></i></div>
        <div class="right">{{ measure_temp }}</div>
      </el-col>
    </el-row>

    <!-- 网关近端 -->
    <el-row class="row">
      <el-col>
        <div class="title">{{ translates.tun }}</div>
        <div class="interval" v-on:click="show_service( 'tun' )">
          <span class="output" v-if="enableds.tun">Auto;&nbsp;</span>
          <span class="output" v-html="colour_actives.tun"></span>
        </div>
        <div v-if="editing == 'tun'" class="top-interval narrow">
          <div>
            <span class="label">本月in：</span>
            {{ expire_info.input }}
          </div>
          <div>
            <span class="label">本月out：</span>
            {{ expire_info.output }}
          </div>
          <div>
            <span class="label">到期：</span>
            {{ expire_info.expire }}
          </div>
          <div class="top-interval right">
            <el-checkbox
              v-model="enableds.tun"
              @change="check_tun"
              :disabled="is_locked">
              开机自动启动
            </el-checkbox>
            <el-button
              @click="editing = null">
              取消
            </el-button>
            <el-button
              @click="systemctl( 'status', 'tun' )"
              :loading="loadings[ 'status@tun' ]"
              :disabled="is_locked">
              刷新
            </el-button>
            <el-button
              v-if="runnings.tun"
              @click="systemctl( 'stop', 'tun' )"
              :loading="loadings[ 'stop@tun' ]"
              :disabled="is_locked">
              停止
            </el-button>
            <el-button
              v-if="!runnings.tun"
              @click="systemctl( 'start', 'tun' )"
              :loading="loadings[ 'start@tun' ]"
              :disabled="is_locked">
              启动
            </el-button>
            <el-button
              v-if="runnings.tun"
              @click="systemctl( 'restart', 'tun' )"
              :loading="loadings[ 'restart@tun' ]"
              :disabled="is_locked">
              重启
            </el-button>
            <el-button
              @click="tail( 'tun' )"
              :disabled="is_locked">
              日志
            </el-button>
          </div>
        </div>
      </el-col>
    </el-row>

    <!-- dns近端 -->
    <el-row class="row">
      <el-col>
        <div class="title">{{ translates.resolv }}</div>
        <div class="interval" v-on:click="show_service( 'resolv' )">
          <span class="output" v-if="enableds.resolv">Auto;&nbsp;</span>
          <span class="output" v-html="colour_actives.resolv"></span>
        </div>
        <div v-if="editing == 'resolv'" class="top-interval narrow">
          <div class="right">
            <el-checkbox
              v-model="enableds.resolv"
              @change="check_resolv"
              :disabled="is_locked">
              开机自动启动
            </el-checkbox>
            <el-button
              @click="editing = null">
              取消
            </el-button>
            <el-button
              @click="systemctl( 'status', 'resolv' )"
              :loading="loadings[ 'status@resolv' ]"
              :disabled="is_locked">
              刷新
            </el-button>
            <el-button
              v-if="runnings.resolv"
              @click="systemctl( 'stop', 'resolv' )"
              :loading="loadings[ 'stop@resolv' ]"
              :disabled="is_locked">
              停止
            </el-button>
            <el-button
              v-if="!runnings.resolv"
              @click="systemctl( 'start', 'resolv' )"
              :loading="loadings[ 'start@resolv' ]"
              :disabled="is_locked">
              启动
            </el-button>
            <el-button
              v-if="runnings.resolv"
              @click="systemctl( 'restart', 'resolv' )"
              :loading="loadings[ 'restart@resolv' ]"
              :disabled="is_locked">
              重启
            </el-button>
            <el-button
              @click="tail( 'resolv' )"
              :disabled="is_locked">
              日志
            </el-button>
          </div>
        </div>
      </el-col>
    </el-row>

    <!-- 热点 -->
    <el-row class="row">
      <el-col>
        <div class="title">{{ translates.hostapd }}</div>
        <div class="interval" v-on:click="show_service( 'hostapd' )">
          <span class="output" v-if="enableds.hostapd">Auto;&nbsp;</span>
          <span class="output" v-html="colour_actives.hostapd"></span>
        </div>
        <div v-if="editing == 'hostapd'" class="top-interval narrow">
          <div class="right">
            <el-checkbox
              v-model="enableds.hostapd"
              @change="check_hostapd"
              :disabled="is_locked">
              开机自动启动
            </el-checkbox>
            <el-button
              @click="editing = null">
              取消
            </el-button>
            <el-button
              @click="systemctl( 'status', 'hostapd' )"
              :loading="loadings[ 'status@hostapd' ]"
              :disabled="is_locked">
              刷新
            </el-button>
            <el-button
              v-if="runnings.hostapd"
              @click="systemctl( 'stop', 'hostapd' )"
              :loading="loadings[ 'stop@hostapd' ]"
              :disabled="is_locked">
              停止
            </el-button>
            <el-button
              v-if="!runnings.hostapd"
              @click="systemctl( 'start', 'hostapd' )"
              :loading="loadings[ 'start@hostapd' ]"
              :disabled="is_locked">
              启动
            </el-button>
            <el-button
              v-if="runnings.hostapd"
              @click="systemctl( 'restart', 'hostapd' )"
              :loading="loadings[ 'restart@hostapd' ]"
              :disabled="is_locked">
              重启
            </el-button>
            <el-button
              @click="tail( 'hostapd' )"
              :disabled="is_locked">
              日志
            </el-button>
            <el-button
              @click="station()"
              :disabled="is_locked">
              客户端
            </el-button>
          </div>
        </div>
      </el-col>
    </el-row>

    <!-- 网卡 -->
    <el-row class="row">
      <el-col>
        <div class="title">{{ translates.dhcpcd }}</div>
        <div class="interval" v-on:click="show_service( 'dhcpcd' )">
          <span class="output" v-if="enableds.dhcpcd">Auto;&nbsp;</span>
          <span class="output" v-html="colour_actives.dhcpcd"></span>
        </div>
        <div v-if="editing == 'dhcpcd'" class="top-interval narrow">
          <div class="right">
            <el-button
              @click="editing = null">
              取消
            </el-button>
            <el-button
              @click="systemctl( 'status', 'dhcpcd' )"
              :loading="loadings[ 'status@dhcpcd' ]"
              :disabled="is_locked">
              刷新
            </el-button>
            <el-button
              v-if="runnings.dhcpcd"
              @click="systemctl( 'restart', 'dhcpcd' )"
              :loading="loadings[ 'restart@dhcpcd' ]"
              :disabled="is_locked">
              重启
            </el-button>
            <el-button
              @click="tail( 'dhcpcd' )"
              :disabled="is_locked">
              日志
            </el-button>
            <el-button
              @click="ip()"
              :disabled="is_locked">
              ip
            </el-button>
          </div>
        </div>
      </el-col>
    </el-row>

    <!-- dhcp租约 -->
    <el-row class="row">
      <el-col>
        <div class="title">{{ translates.dnsmasq }}</div>
        <div class="interval" v-on:click="show_service( 'dnsmasq' )">
          <span class="output" v-if="enableds.dnsmasq">Auto;&nbsp;</span>
          <span class="output" v-html="colour_actives.dnsmasq"></span>
        </div>
        <div v-if="editing == 'dnsmasq'" class="top-interval narrow">
          <div class="right">
            <el-button
              @click="editing = null">
              取消
            </el-button>
            <el-button
              @click="systemctl( 'status', 'dnsmasq' )"
              :loading="loadings[ 'status@dnsmasq' ]"
              :disabled="is_locked">
              刷新
            </el-button>
            <el-button
              v-if="runnings.dnsmasq"
              @click="systemctl( 'restart', 'dnsmasq' )"
              :loading="loadings[ 'restart@dnsmasq' ]"
              :disabled="is_locked">
              重启
            </el-button>
            <el-button
              @click="tail( 'dnsmasq' )"
              :disabled="is_locked">
              日志
            </el-button>
          </div>
        </div>
      </el-col>
    </el-row>

    <!-- 远端地址 -->
    <el-row class="row">
      <el-col>
        <div class="title">{{ translates[ 'girl.tund' ] }}</div>
        <div v-if="editing == 'girl.tund'" class="interval narrow">
          <el-input
            type="textarea"
            :rows="10"
            v-model="texts[ 'girl.tund' ]"
            autofocus>
          </el-input>
          <div class="right top-interval">
            <el-button
              @click="editing = null">
              取消
            </el-button>
            <el-button
              @click="save_text( 'girl.tund' )"
              :loading="loadings[ 'save@girl.tund' ]"
              :disabled="is_locked">
              保存
            </el-button>
          </div>
        </div>
        <div v-else>
          <div
            v-html="texts[ 'girl.tund' ] ? texts[ 'girl.tund' ].replace( new RegExp( /\n/, 'g' ), '<br />' ) : ''"
            v-on:click="editing = 'girl.tund'"
            class="output output-area interval narrow"
          />
        </div>
      </el-col>
    </el-row>

    <!-- 自定义 -->
    <el-row class="row">
      <el-col>
        <div class="title">{{ translates[ 'girl.custom.txt' ] }}</div>
        <div v-if="editing == 'girl.custom.txt'" class="interval narrow">
          <el-input
            type="textarea"
            :rows="10"
            v-model="texts[ 'girl.custom.txt' ]"
            autofocus>
          </el-input>
          <div class="right top-interval">
            <el-button
              @click="editing = null">
              取消
            </el-button>
            <el-button
              @click="save_text( 'girl.custom.txt' )"
              :loading="loadings[ 'save@girl.custom.txt' ]"
              :disabled="is_locked">
              保存
            </el-button>
          </div>
          <div class="top-interval">
            例子：<br /><br />
            <span class="sample">
              google.com
            </span>
            <span class="desc">
              表示：google.com dns查询走远端。
            </span><br />
            <span class="sample">
              69.63.32.36
            </span>
            <span class="desc">
              表示：69.63.32.36 走远端。
            </span><br />
            <span class="sample">
              &nbsp;
            </span>
            <span class="desc">
              通常情况不需要填写ip，<a target="_blank" :href="http_host + '/chnroute.txt'">国内ip段</a>之外的ip默认走远端。
            </span><br />
            <span class="sample">
              !69.63.32.36
            </span>
            <span class="desc">
              表示：69.63.32.36 不走远端。前缀 “!” 表示忽略。
            </span><br />
            <span class="sample">
              !69.63.32.36 # 忽略tasvideos
            </span>
            <span class="desc">
              “#” 接注释。
            </span><br />
            <span class="sample">
              &nbsp;
            </span>
            <span class="desc">
              一行一个。
            </span><br />
          </div>
        </div>
        <div v-else>
          <div
            v-html="texts[ 'girl.custom.txt' ] ? texts[ 'girl.custom.txt' ].replace( new RegExp( /\n/, 'g' ), '<br />' ) : ''"
            v-on:click="editing = 'girl.custom.txt'"
            class="output output-area interval narrow"
          />
        </div>
      </el-col>
    </el-row>

    <!-- 热点配置 -->
    <el-row class="row">
      <el-col>
        <div class="title">{{ translates[ 'hostapd.conf' ] }}</div>
        <div v-if="editing == 'hostapd.conf'" class="interval narrow">
          <el-input
            type="textarea"
            :rows="10"
            v-model="texts[ 'hostapd.conf' ]"
            autofocus>
          </el-input>
          <div class="right top-interval">
            <el-button
              @click="editing = null">
              取消
            </el-button>
            <el-button
              @click="save_text( 'hostapd.conf' )"
              :loading="loadings[ 'save@hostapd.conf' ]"
              :disabled="is_locked">
              保存
            </el-button>
          </div>
          <div class="top-interval">
            设置wifi名称，更改 ssid 行。<br />
            设置wifi密码，wpa=2，更改 wpa_passphrase 行。<br />
            设置是否隐藏，更改 ignore_broadcast_ssid 行。取值：0显示，1隐藏。
          </div>
        </div>
        <div v-else>
          <div
            v-html="texts[ 'hostapd.conf' ] ? texts[ 'hostapd.conf' ].replace( new RegExp( /\n/, 'g' ), '<br />' ) : ''"
            v-on:click="editing = 'hostapd.conf'"
            class="output output-area interval narrow"
          />
        </div>
      </el-col>
    </el-row>

    <!-- dns默认地址 -->
    <el-row class="row">
      <el-col>
        <div class="title">{{ translates[ 'nameservers.txt' ] }}</div>
        <div v-if="editing == 'nameservers.txt'" class="interval narrow">
          <el-input
            type="textarea"
            :rows="10"
            v-model="texts[ 'nameservers.txt' ]"
            autofocus>
          </el-input>
          <div class="right top-interval">
            <el-button
              @click="editing = null">
              取消
            </el-button>
            <el-button
              @click="save_text( 'nameservers.txt' )"
              :loading="loadings[ 'save@nameservers.txt' ]"
              :disabled="is_locked">
              保存
            </el-button>
          </div>
        </div>
        <div v-else>
          <div
            v-html="texts[ 'nameservers.txt' ] ? texts[ 'nameservers.txt' ].replace( new RegExp( /\n/, 'g' ), '<br />' ) : ''"
            v-on:click="editing = 'nameservers.txt'"
            class="output output-area interval narrow"
          />
        </div>
      </el-col>
    </el-row>

    <!-- 网卡配置 -->
    <el-row class="row">
      <el-col>
        <div class="title">{{ translates[ 'dhcpcd.conf' ] }}</div>
        <div v-if="editing == 'dhcpcd.conf'" class="interval narrow">
          <el-input
            type="textarea"
            :rows="10"
            v-model="texts[ 'dhcpcd.conf' ]"
            autofocus>
          </el-input>
          <div class="right top-interval">
            <el-button
              @click="editing = null">
              取消
            </el-button>
            <el-button
              @click="save_text( 'dhcpcd.conf' )"
              :loading="loadings[ 'save@dhcpcd.conf' ]"
              :disabled="is_locked">
              保存
            </el-button>
          </div>
          <div class="top-interval">
            若更改了ip地址，请在地址栏输入新的ip地址，以访问本界面。
          </div>
        </div>
        <div v-else>
          <div
            v-html="texts[ 'dhcpcd.conf' ] ? texts[ 'dhcpcd.conf' ].replace( new RegExp( /\n/, 'g' ), '<br />' ) : ''"
            v-on:click="editing = 'dhcpcd.conf'"
            class="output output-area interval narrow"
          />
        </div>
      </el-col>
    </el-row>

    <!-- dhcp租约配置 -->
    <el-row class="row">
      <el-col>
        <div class="title">{{ translates[ 'dnsmasq.d/wlan0.conf' ] }}</div>
        <div v-if="editing == 'dnsmasq.d/wlan0.conf'" class="interval narrow">
          <el-input
            type="textarea"
            :rows="10"
            v-model="texts[ 'dnsmasq.d/wlan0.conf' ]"
            autofocus>
          </el-input>
          <div class="right top-interval">
            <el-button
              @click="editing = null">
              取消
            </el-button>
            <el-button
              @click="save_text( 'dnsmasq.d/wlan0.conf' )"
              :loading="loadings[ 'save@dnsmasq.d/wlan0.conf' ]"
              :disabled="is_locked">
              保存
            </el-button>
          </div>
        </div>
        <div v-else>
          <div
            v-html="texts[ 'dnsmasq.d/wlan0.conf' ] ? texts[ 'dnsmasq.d/wlan0.conf' ].replace( new RegExp( /\n/, 'g' ), '<br />' ) : ''"
            v-on:click="editing = 'dnsmasq.d/wlan0.conf'"
            class="output output-area interval narrow"
          />
        </div>
      </el-col>
    </el-row>

    <el-row>
      <el-col id="footer">
        <img id="shadow" src="./assets/shadow.jpg" />
      </el-col>
    </el-row>
  </div>
</template>

<script src="./app.js"></script>
