<template>
  <div id="app">
    <div id="header">
      <div><img src="./assets/bear.jpg" /></div>
      <div v-if="conf.im">{{ conf.im }}</div>
      <div class="right" v-if="is_locked"><i class="el-icon-lock"></i></div>
    </div>

    <div id="main">
      <!-- 代理近端 -->
      <el-row class="row">
        <el-col>
          <div class="title">{{ translates.proxy }}</div>
          <div class="interval" v-on:click="show_service( 'proxy' )">
            <span class="output" v-if="enableds.proxy">Auto;&nbsp;</span>
            <span class="output" v-html="colour_actives.proxy"></span>
          </div>
          <div v-if="editing == 'proxy' && !is_locked" class="mw600">
            <div>
              <span class="label">本月in：</span>
              {{ expire_info.input }}
            </div>
            <div>
              <span class="label">本月out：</span>
              {{ expire_info.output }}
            </div>
            <div>
              <span class="label">远端到期：</span>
              {{ expire_info.expire }}
            </div>
            <div class="right top-interval">
              <el-checkbox
                v-model="enableds.proxy"
                @change="check_proxy">
                开机自启
              </el-checkbox>&nbsp;&nbsp;
              <el-button
                @click="editing = null">
                取消
              </el-button>
              <el-button
                @click="systemctl( 'status', 'proxy' )"
                :loading="loadings[ 'status@proxy' ]">
                刷新
              </el-button>
              <el-button
                v-if="runnings.proxy"
                @click="systemctl( 'stop', 'proxy' )"
                :loading="loadings[ 'stop@proxy' ]">
                停止
              </el-button>
              <el-button
                v-if="!runnings.proxy"
                @click="systemctl( 'start', 'proxy' )"
                :loading="loadings[ 'start@proxy' ]">
                启动
              </el-button>
              <el-button
                v-if="runnings.proxy"
                @click="systemctl( 'restart', 'proxy' )"
                :loading="loadings[ 'restart@proxy' ]">
                重启
              </el-button>
              <el-button
                @click="tail( 'proxy' )">
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
          <div v-if="editing == 'hostapd' && !is_locked" class="mw600">
            <div class="right">
              <el-checkbox
                v-model="enableds.hostapd"
                @change="check_hostapd">
                开机自启
              </el-checkbox>&nbsp;&nbsp;
              <el-button
                @click="editing = null">
                取消
              </el-button>
              <el-button
                @click="systemctl( 'status', 'hostapd' )"
                :loading="loadings[ 'status@hostapd' ]">
                刷新
              </el-button>
              <el-button
                v-if="runnings.hostapd"
                @click="systemctl( 'stop', 'hostapd' )"
                :loading="loadings[ 'stop@hostapd' ]">
                停止
              </el-button>
              <el-button
                v-if="!runnings.hostapd"
                @click="systemctl( 'start', 'hostapd' )"
                :loading="loadings[ 'start@hostapd' ]">
                启动
              </el-button>
              <el-button
                v-if="runnings.hostapd"
                @click="systemctl( 'restart', 'hostapd' )"
                :loading="loadings[ 'restart@hostapd' ]">
                重启
              </el-button>
              <el-button
                @click="tail( 'hostapd' )">
                日志
              </el-button>
              <el-button
                @click="station()">
                设备
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
          <div v-if="editing == 'dhcpcd' && !is_locked" class="mw600">
            <div class="right">
              <el-button
                @click="editing = null">
                取消
              </el-button>
              <el-button
                @click="systemctl( 'status', 'dhcpcd' )"
                :loading="loadings[ 'status@dhcpcd' ]">
                刷新
              </el-button>
              <el-button
                v-if="runnings.dhcpcd"
                @click="systemctl( 'restart', 'dhcpcd' )"
                :loading="loadings[ 'restart@dhcpcd' ]">
                重启
              </el-button>
              <el-button
                @click="tail( 'dhcpcd' )">
                日志
              </el-button>
              <el-button
                @click="ip()">
                地址
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
          <div v-if="editing == 'dnsmasq' && !is_locked" class="mw600">
            <div class="right">
              <el-button
                @click="editing = null">
                取消
              </el-button>
              <el-button
                @click="systemctl( 'status', 'dnsmasq' )"
                :loading="loadings[ 'status@dnsmasq' ]">
                刷新
              </el-button>
              <el-button
                v-if="runnings.dnsmasq"
                @click="systemctl( 'restart', 'dnsmasq' )"
                :loading="loadings[ 'restart@dnsmasq' ]">
                重启
              </el-button>
              <el-button
                @click="tail( 'dnsmasq' )">
                日志
              </el-button>
            </div>
          </div>
        </el-col>
      </el-row>

      <!-- 交给远端解析的域名列表 -->
      <el-row class="row">
        <el-col>
          <div class="title">{{ translates[ 'girl.remote.txt' ] }}</div>
          <div v-if="editing == 'girl.remote.txt' && !is_locked" class="interval mw300">
            <el-input
              type="textarea"
              :rows="4"
              v-model="texts[ 'girl.remote.txt' ]"
              autofocus>
            </el-input>
            <div class="right top-interval">
              <el-button
                @click="editing = null">
                取消
              </el-button>
              <el-button
                @click="save_text( 'girl.remote.txt' )"
                :loading="loadings[ 'save@girl.remote.txt' ]">
                保存
              </el-button>
            </div>
          </div>
          <div v-else class="interval mw300">
            <div
              v-html="texts[ 'girl.remote.txt' ] ? texts[ 'girl.remote.txt' ].replace( new RegExp( /\n/, 'g' ), '<br />' ) : ''"
              v-on:click="editing = 'girl.remote.txt'"
              class="output output-area"
            />
          </div>
        </el-col>
      </el-row>

      <!-- 热点配置 -->
      <el-row class="row">
        <el-col>
          <div class="title">{{ translates[ 'hostapd.conf' ] }}</div>
          <div v-if="editing == 'hostapd.conf' && !is_locked" class="interval mw300">
            <el-input
              type="textarea"
              :rows="4"
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
                :loading="loadings[ 'save@hostapd.conf' ]">
                保存
              </el-button>
            </div>
            <div class="top-interval">
              设置wifi名称，更改 ssid 行。<br />
              设置wifi密码，更改 wpa_passphrase 行。<br />
              设置是否隐藏，更改 ignore_broadcast_ssid 行。取值：0显示，1隐藏。
            </div>
          </div>
          <div v-else class="interval mw300">
            <div
              v-html="texts[ 'hostapd.conf' ] ? texts[ 'hostapd.conf' ].replace( new RegExp( /\n/, 'g' ), '<br />' ) : ''"
              v-on:click="editing = 'hostapd.conf'"
              class="output output-area"
            />
          </div>
        </el-col>
      </el-row>

      <!-- 网卡配置 -->
      <el-row class="row">
        <el-col>
          <div class="title">{{ translates[ 'dhcpcd.conf' ] }}</div>
          <div v-if="editing == 'dhcpcd.conf' && !is_locked" class="interval mw300">
            <el-input
              type="textarea"
              :rows="4"
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
                :loading="loadings[ 'save@dhcpcd.conf' ]">
                保存
              </el-button>
            </div>
            <div class="top-interval">
              若更改了ip地址，请在地址栏输入新的ip地址，以访问本界面。
            </div>
          </div>
          <div v-else class="interval mw300">
            <div
              v-html="texts[ 'dhcpcd.conf' ] ? texts[ 'dhcpcd.conf' ].replace( new RegExp( /\n/, 'g' ), '<br />' ) : ''"
              v-on:click="editing = 'dhcpcd.conf'"
              class="output output-area"
            />
          </div>
        </el-col>
      </el-row>

      <!-- dhcp租约配置 -->
      <el-row class="row">
        <el-col>
          <div class="title">{{ translates[ 'dnsmasq.d/wlan0.conf' ] }}</div>
          <div v-if="editing == 'dnsmasq.d/wlan0.conf' && !is_locked" class="interval mw300">
            <el-input
              type="textarea"
              :rows="4"
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
                :loading="loadings[ 'save@dnsmasq.d/wlan0.conf' ]">
                保存
              </el-button>
            </div>
          </div>
          <div v-else class="interval mw300">
            <div
              v-html="texts[ 'dnsmasq.d/wlan0.conf' ] ? texts[ 'dnsmasq.d/wlan0.conf' ].replace( new RegExp( /\n/, 'g' ), '<br />' ) : ''"
              v-on:click="editing = 'dnsmasq.d/wlan0.conf'"
              class="output output-area"
            />
          </div>
        </el-col>
      </el-row>
    </div>

    <div id="footer">
    </div>
  </div>
</template>

<script src="./app.js"></script>
