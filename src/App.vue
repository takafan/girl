<template>
  <div id="app">

    <el-row>
      <el-col :span="1">&nbsp;</el-col>
      <el-col :span="22" id="header">
        <div><img id="bear" src="./assets/bear.jpg" /></div>
        <span v-if="is_locked">&nbsp;<Icon type="md-lock" /></span>
      </el-col>
      <el-col :span="1">&nbsp;</el-col>
    </el-row>

    <el-row class="row">
      <el-col :span="1">&nbsp;</el-col>
      <el-col :span="22">
        <div class="title bold">{{ translates.tun }}</div>
        <div class="interval">
          <span class="output" v-html="colour_actives.tun" v-on:click="show_service( 'tun' )"></span>
        </div>
        <div v-if="editing == 'tun'" class="top-interval mw550">
          <div v-if="expire_info" v-html="expire_info"></div>
          <div class="top-interval right">
            <span>
              <el-checkbox v-model="enableds.tun" @change="check_tun" :disabled="is_locked">开机自动启动</el-checkbox>
            </span>
            <span>
              &nbsp;&nbsp;
              <el-button @click="editing = null">取消</el-button>
            </span>
            <span>
              &nbsp;&nbsp;
              <el-button @click="systemctl( 'status', 'tun' )" :loading="loadings[ 'status@tun' ]" :disabled="is_locked">刷新</el-button>
            </span>
            <span v-if="runnings.tun">
              &nbsp;&nbsp;
              <el-button @click="systemctl( 'stop', 'tun' )" :loading="loadings[ 'stop@tun' ]" :disabled="is_locked">停止</el-button>
            </span>
            <span v-if="!runnings.tun">
              &nbsp;&nbsp;
              <el-button @click="systemctl( 'start', 'tun' )" :loading="loadings[ 'start@tun' ]" :disabled="is_locked">启动</el-button>
            </span>
            <span v-if="runnings.tun">
              &nbsp;&nbsp;
              <el-button @click="systemctl( 'restart', 'tun' )" :loading="loadings[ 'restart@tun' ]" :disabled="is_locked">重启</el-button>
            </span>
            <span>
              &nbsp;&nbsp;
              <el-button @click="tail( 'tun' )" :disabled="is_locked">日志</el-button>
            </span>
          </div>
        </div>
      </el-col>
      <el-col :span="1">&nbsp;</el-col>
    </el-row>
    <el-row class="row">
      <el-col :span="1">&nbsp;</el-col>
      <el-col :span="22">
        <div class="title bold">{{ translates.resolv }}</div>
        <div class="interval">
          <span class="output" v-html="colour_actives.resolv" v-on:click="show_service( 'resolv' )"></span>
        </div>
        <div v-if="editing == 'resolv'" class="top-interval mw550">
          <div class="right">
            <span>
              <el-checkbox v-model="enableds.resolv" @change="check_resolv" :disabled="is_locked">开机自动启动</el-checkbox>
            </span>
            <span>
              &nbsp;&nbsp;
              <el-button @click="editing = null">取消</el-button>
            </span>
            <span>
              &nbsp;&nbsp;
              <el-button @click="systemctl( 'status', 'resolv' )" :loading="loadings[ 'status@resolv' ]" :disabled="is_locked">刷新</el-button>
            </span>
            <span v-if="runnings.resolv">
              &nbsp;&nbsp;
              <el-button @click="systemctl( 'stop', 'resolv' )" :loading="loadings[ 'stop@resolv' ]" :disabled="is_locked">停止</el-button>
            </span>
            <span v-if="!runnings.resolv">
              &nbsp;&nbsp;
              <el-button @click="systemctl( 'start', 'resolv' )" :loading="loadings[ 'start@resolv' ]" :disabled="is_locked">启动</el-button>
            </span>
            <span v-if="runnings.resolv">
              &nbsp;&nbsp;
              <el-button @click="systemctl( 'restart', 'resolv' )" :loading="loadings[ 'restart@resolv' ]" :disabled="is_locked">重启</el-button>
            </span>
            <span>
              &nbsp;&nbsp;
              <el-button @click="tail( 'resolv' )" :disabled="is_locked">日志</el-button>
            </span>
          </div>
        </div>
      </el-col>
      <el-col :span="1">&nbsp;</el-col>
    </el-row>
    <el-row class="row">
      <el-col :span="1">&nbsp;</el-col>
      <el-col :span="22">
        <div class="title bold">{{ translates.hostapd }}</div>
        <div class="interval">
          <span class="output" v-html="colour_actives.hostapd" v-on:click="show_service( 'hostapd' )"></span>
        </div>
        <div v-if="editing == 'hostapd'" class="top-interval mw550">
          <div class="right">
            <span>
              <el-checkbox v-model="enableds.hostapd" @change="check_hostapd" :disabled="is_locked">开机自动启动</el-checkbox>
            </span>
            <span>
              &nbsp;&nbsp;
              <el-button @click="editing = null">取消</el-button>
            </span>
            <span>
              &nbsp;&nbsp;
              <el-button @click="systemctl( 'status', 'hostapd' )" :loading="loadings[ 'status@hostapd' ]" :disabled="is_locked">刷新</el-button>
            </span>
            <span v-if="runnings.hostapd">
              &nbsp;&nbsp;
              <el-button @click="systemctl( 'stop', 'hostapd' )" :loading="loadings[ 'stop@hostapd' ]" :disabled="is_locked">停止</el-button>
            </span>
            <span v-if="!runnings.hostapd">
              &nbsp;&nbsp;
              <el-button @click="systemctl( 'start', 'hostapd' )" :loading="loadings[ 'start@hostapd' ]" :disabled="is_locked">启动</el-button>
            </span>
            <span v-if="runnings.hostapd">
              &nbsp;&nbsp;
              <el-button @click="systemctl( 'restart', 'hostapd' )" :loading="loadings[ 'restart@hostapd' ]" :disabled="is_locked">重启</el-button>
            </span>
            <span>
              &nbsp;&nbsp;
              <el-button @click="tail( 'hostapd' )" :disabled="is_locked">日志</el-button>
            </span>
            <span>
              &nbsp;&nbsp;
              <el-button @click="station()" :disabled="is_locked">客户端</el-button>
            </span>
          </div>
        </div>
      </el-col>
      <el-col :span="1">&nbsp;</el-col>
    </el-row>
    <el-row class="row">
      <el-col :span="1">&nbsp;</el-col>
      <el-col :span="22">
        <div class="title bold">{{ translates.dhcpcd }}</div>
        <div class="interval">
          <span class="output" v-html="colour_actives.dhcpcd" v-on:click="show_service( 'dhcpcd' )"></span>
        </div>
        <div v-if="editing == 'dhcpcd'" class="top-interval mw550">
          <div class="right">
            <span>
              <el-button @click="editing = null">取消</el-button>
            </span>
            <span>
              &nbsp;&nbsp;
              <el-button @click="systemctl( 'status', 'dhcpcd' )" :loading="loadings[ 'status@dhcpcd' ]" :disabled="is_locked">刷新</el-button>
            </span>
            <span v-if="runnings.dhcpcd">
              &nbsp;&nbsp;
              <el-button @click="systemctl( 'restart', 'dhcpcd' )" :loading="loadings[ 'restart@dhcpcd' ]" :disabled="is_locked">重启</el-button>
            </span>
            <span>
              &nbsp;&nbsp;
              <el-button @click="tail( 'dhcpcd' )" :disabled="is_locked">日志</el-button>
            </span>
            <span>
              &nbsp;&nbsp;
              <el-button @click="ip()" :disabled="is_locked">ip</el-button>
            </span>
          </div>
        </div>
      </el-col>
      <el-col :span="1">&nbsp;</el-col>
    </el-row>
    <el-row class="row">
      <el-col :span="1">&nbsp;</el-col>
      <el-col :span="22">
        <div class="title bold">{{ translates.dnsmasq }}</div>
        <div class="interval">
          <span class="output" v-html="colour_actives.dnsmasq" v-on:click="show_service( 'dnsmasq' )"></span>
        </div>
        <div v-if="editing == 'dnsmasq'" class="top-interval mw550">
          <div class="right">
            <span>
              <el-button @click="editing = null">取消</el-button>
            </span>
            <span>
              &nbsp;&nbsp;
              <el-button @click="systemctl( 'status', 'dnsmasq' )" :loading="loadings[ 'status@dnsmasq' ]" :disabled="is_locked">刷新</el-button>
            </span>
            <span v-if="runnings.dnsmasq">
              &nbsp;&nbsp;
              <el-button @click="systemctl( 'restart', 'dnsmasq' )" :loading="loadings[ 'restart@dnsmasq' ]" :disabled="is_locked">重启</el-button>
            </span>
            <span>
              &nbsp;&nbsp;
              <el-button @click="tail( 'dnsmasq' )" :disabled="is_locked">日志</el-button>
            </span>
          </div>
        </div>
      </el-col>
      <el-col :span="1">&nbsp;</el-col>
    </el-row>

    <el-row class="row">
      <el-col :span="1">&nbsp;</el-col>
      <el-col :span="22">
        <div class="title bold">{{ translates[ 'girl.tund' ] }}</div>
        <div v-if="editing == 'girl.tund'" class="interval mw550">
          <Input type="textarea" :rows="10" v-model="texts[ 'girl.tund' ]" autofocus></Input>
          <div class="right top-interval">
            <el-button @click="editing = null">取消</el-button>
            &nbsp;&nbsp;
            <el-button @click="save_text( 'girl.tund' )" :loading="loadings[ 'save@girl.tund' ]" :disabled="is_locked">保存</el-button>
          </div>
        </div>
        <div v-else>
          <div v-html="texts[ 'girl.tund' ] ? texts[ 'girl.tund' ].replace( new RegExp( /\n/, 'g' ), '<br />' ) : ''"
            v-on:click="editing = 'girl.tund'"
            class="output mh200 output-area interval mw550"
          />
          <div v-if="saved == 'girl.tund'" class="mw550 right">
            <div> 配置生效需要重启{{ translates.tun }}，确认重启服务吗？ </div>
            <div class="top-interval">
              <el-button @click="saved = null">取消</el-button>
              &nbsp;&nbsp;
              <el-button @click="systemctl( 'restart', 'tun' )" :loading="loadings[ 'restart@tun' ]" :disabled="is_locked">重启{{ translates.tun }}</el-button>
            </div>
          </div>
        </div>
      </el-col>
      <el-col :span="1">&nbsp;</el-col>
    </el-row>
    <el-row class="row">
      <el-col :span="1">&nbsp;</el-col>
      <el-col :span="22">
        <div class="title bold">{{ translates[ 'girl.resolvd' ] }}</div>
        <div v-if="editing == 'girl.resolvd'" class="interval mw550">
          <Input type="textarea" :rows="10" v-model="texts[ 'girl.resolvd' ]" autofocus></Input>
          <div class="right top-interval">
            <el-button @click="editing = null">取消</el-button>
            &nbsp;&nbsp;
            <el-button @click="save_text( 'girl.resolvd' )" :loading="loadings[ 'save@girl.resolvd' ]" :disabled="is_locked">保存</el-button>
          </div>
        </div>
        <div v-else>
          <div v-html="texts[ 'girl.resolvd' ] ? texts[ 'girl.resolvd' ].replace( new RegExp( /\n/, 'g' ), '<br />' ) : ''"
            v-on:click="editing = 'girl.resolvd'"
            class="output mh200 output-area interval mw550"
          />
          <div v-if="saved == 'girl.resolvd'" class="mw550 right">
            <div> 配置生效需要重启{{ translates.resolv }}，确认重启服务吗？ </div>
            <div class="top-interval">
              <el-button @click="saved = null">取消</el-button>
              &nbsp;&nbsp;
              <el-button @click="systemctl( 'restart', 'resolv' )" :loading="loadings[ 'restart@resolv' ]" :disabled="is_locked">重启{{ translates.resolv }}</el-button>
            </div>
          </div>
        </div>
      </el-col>
      <el-col :span="1">&nbsp;</el-col>
    </el-row>
    <el-row class="row">
      <el-col :span="1">&nbsp;</el-col>
      <el-col :span="22">
        <div class="title bold">{{ translates[ 'nameservers.txt' ] }}</div>
        <div v-if="editing == 'nameservers.txt'" class="interval mw550">
          <Input type="textarea" :rows="10" v-model="texts[ 'nameservers.txt' ]" autofocus></Input>
          <div class="right top-interval">
            <el-button @click="editing = null">取消</el-button>
            &nbsp;&nbsp;
            <el-button @click="save_text( 'nameservers.txt' )" :loading="loadings[ 'save@nameservers.txt' ]" :disabled="is_locked">保存</el-button>
          </div>
        </div>
        <div v-else>
          <div v-html="texts[ 'nameservers.txt' ] ? texts[ 'nameservers.txt' ].replace( new RegExp( /\n/, 'g' ), '<br />' ) : ''"
            v-on:click="editing = 'nameservers.txt'"
            class="output mh200 output-area interval mw550"
          />
          <div v-if="saved == 'nameservers.txt'" class="mw550 right">
            <div> 配置生效需要重启{{ translates.resolv }}，确认重启服务吗？ </div>
            <div class="top-interval">
              <el-button @click="saved = null">取消</el-button>
              &nbsp;&nbsp;
              <el-button @click="systemctl( 'restart', 'resolv' )" :loading="loadings[ 'restart@resolv' ]" :disabled="is_locked">重启{{ translates.resolv }}</el-button>
            </div>
          </div>
        </div>
      </el-col>
      <el-col :span="1">&nbsp;</el-col>
    </el-row>
    <el-row class="row">
      <el-col :span="1">&nbsp;</el-col>
      <el-col :span="22">
        <div class="title bold">{{ translates[ 'girl.custom.txt' ] }}</div>
        <div v-if="editing == 'girl.custom.txt'" class="interval mw550">
          <Input type="textarea" :rows="10" v-model="texts[ 'girl.custom.txt' ]" autofocus></Input>
          <div class="right top-interval">
            <el-button @click="editing = null">取消</el-button>
            &nbsp;&nbsp;
            <el-button @click="save_text( 'girl.custom.txt' )" :loading="loadings[ 'save@girl.custom.txt' ]" :disabled="is_locked">保存</el-button>
          </div>
          <div class="top-interval">
            填写域名，该域名dns查询走远端。例如：google.com<br />
            一行一个。<br />
            填写ip，该ip走远端。例如：69.63.32.36<br />
            通常情况不需要填写ip，<a target="_blank" :href="http_host + '/chnroute.txt'">国内ip段</a>之外的ip默认走远端。<br />
            前缀 “!” 表示忽略，不走远端。例如：!69.63.32.36<br />
            “#” 接注释。例如：!69.63.32.36 # 忽略tasvideos
          </div>
        </div>
        <div v-else>
          <div v-html="texts[ 'girl.custom.txt' ] ? texts[ 'girl.custom.txt' ].replace( new RegExp( /\n/, 'g' ), '<br />' ) : ''"
            v-on:click="editing = 'girl.custom.txt'"
            class="output mh200 output-area interval mw550"
          />
          <div v-if="saved == 'girl.custom.txt'" class="mw550 right">
            <div> 域名生效需要重启{{ translates.resolv }}，ip生效需要重启{{ translates.tun }}，选择要重启的服务： </div>
            <div class="top-interval">
              <el-button @click="saved = null">取消</el-button>
              &nbsp;&nbsp;
              <el-button @click="systemctl( 'restart', 'tun' )" :loading="loadings[ 'restart@tun' ]" :disabled="is_locked">重启{{ translates.tun }}</el-button>
              &nbsp;&nbsp;
              <el-button @click="systemctl( 'restart', 'resolv' )" :loading="loadings[ 'restart@resolv' ]" :disabled="is_locked">重启{{ translates.resolv }}</el-button>
            </div>
          </div>
        </div>
      </el-col>
      <el-col :span="1">&nbsp;</el-col>
    </el-row>
    <el-row class="row">
      <el-col :span="1">&nbsp;</el-col>
      <el-col :span="22">
        <div class="title bold">{{ translates[ 'hostapd.conf' ] }}</div>
        <div v-if="editing == 'hostapd.conf'" class="interval mw550">
          <Input type="textarea" :rows="10" v-model="texts[ 'hostapd.conf' ]" autofocus></Input>
          <div class="right top-interval">
            <el-button @click="editing = null">取消</el-button>
            &nbsp;&nbsp;
            <el-button @click="save_text( 'hostapd.conf' )" :loading="loadings[ 'save@hostapd.conf' ]" :disabled="is_locked">保存</el-button>
          </div>
          <div class="top-interval">
            设置wifi名称，更改 ssid 行。<br />
            设置wifi密码，wpa=2，更改 wpa_passphrase 行。<br />
            设置是否隐藏，更改 ignore_broadcast_ssid 行。取值：0显示，1隐藏。
          </div>
        </div>
        <div v-else>
          <div v-html="texts[ 'hostapd.conf' ] ? texts[ 'hostapd.conf' ].replace( new RegExp( /\n/, 'g' ), '<br />' ) : ''"
            v-on:click="editing = 'hostapd.conf'"
            class="output mh200 output-area interval mw550"
          />
          <div v-if="saved == 'hostapd.conf'" class="mw550 right">
            <div> 配置生效需要重启{{ translates.hostapd }}，确认重启服务吗？ </div>
            <div class="top-interval">
              <el-button @click="saved = null">取消</el-button>
              &nbsp;&nbsp;
              <el-button @click="systemctl( 'restart', 'hostapd' )" :loading="loadings[ 'restart@hostapd' ]" :disabled="is_locked">重启{{ translates.hostapd }}</el-button>
            </div>
          </div>
        </div>
      </el-col>
      <el-col :span="1">&nbsp;</el-col>
    </el-row>
    <el-row class="row">
      <el-col :span="1">&nbsp;</el-col>
      <el-col :span="22">
        <div class="title bold">{{ translates[ 'dhcpcd.conf' ] }}</div>
        <div v-if="editing == 'dhcpcd.conf'" class="interval mw550">
          <Input type="textarea" :rows="10" v-model="texts[ 'dhcpcd.conf' ]" autofocus></Input>
          <div class="right top-interval">
            <el-button @click="editing = null">取消</el-button>
            &nbsp;&nbsp;
            <el-button @click="save_text( 'dhcpcd.conf' )" :loading="loadings[ 'save@dhcpcd.conf' ]" :disabled="is_locked">保存</el-button>
          </div>
        </div>
        <div v-else>
          <div v-html="texts[ 'dhcpcd.conf' ] ? texts[ 'dhcpcd.conf' ].replace( new RegExp( /\n/, 'g' ), '<br />' ) : ''"
            v-on:click="editing = 'dhcpcd.conf'"
            class="output mh200 output-area interval mw550"
          />
          <div v-if="saved == 'dhcpcd.conf'" class="mw550 right">
            <div> 配置生效需要重启{{ translates.dhcpcd }}，确认重启服务吗？ </div>
            <div class="top-interval">
              <el-button @click="saved = null">取消</el-button>
              &nbsp;&nbsp;
              <el-button @click="systemctl( 'restart', 'dhcpcd' )" :loading="loadings[ 'restart@dhcpcd' ]" :disabled="is_locked">重启{{ translates.dhcpcd }}</el-button>
            </div>
          </div>
        </div>
      </el-col>
      <el-col :span="1">&nbsp;</el-col>
    </el-row>
    <el-row class="row">
      <el-col :span="1">&nbsp;</el-col>
      <el-col :span="22">
        <div class="title bold">{{ translates[ 'dnsmasq.d/wlan0.conf' ] }}</div>
        <div v-if="editing == 'dnsmasq.d/wlan0.conf'" class="interval mw550">
          <Input type="textarea" :rows="10" v-model="texts[ 'dnsmasq.d/wlan0.conf' ]" autofocus></Input>
          <div class="right top-interval">
            <el-button @click="editing = null">取消</el-button>
            &nbsp;&nbsp;
            <el-button @click="save_text( 'dnsmasq.d/wlan0.conf' )" :loading="loadings[ 'save@dnsmasq.d/wlan0.conf' ]" :disabled="is_locked">保存</el-button>
          </div>
        </div>
        <div v-else>
          <div v-html="texts[ 'dnsmasq.d/wlan0.conf' ] ? texts[ 'dnsmasq.d/wlan0.conf' ].replace( new RegExp( /\n/, 'g' ), '<br />' ) : ''"
            v-on:click="editing = 'dnsmasq.d/wlan0.conf'"
            class="output mh200 output-area interval mw550"
          />
          <div v-if="saved == 'dnsmasq.d/wlan0.conf'" class="mw550 right">
            <div> 配置生效需要重启{{ translates.dnsmasq }}，确认重启服务吗？ </div>
            <div class="top-interval">
              <el-button @click="saved = null">取消</el-button>
              &nbsp;&nbsp;
              <el-button @click="systemctl( 'restart', 'dnsmasq' )" :loading="loadings[ 'restart@dnsmasq' ]" :disabled="is_locked">重启{{ translates.dnsmasq }}</el-button>
            </div>
          </div>
        </div>
      </el-col>
      <el-col :span="1">&nbsp;</el-col>
    </el-row>
    <el-row class="row">
      <el-col :span="1">&nbsp;</el-col>
      <el-col :span="22">
        <div class="title bold">{{ translates[ 'girl.p2pd' ] }}</div>
        <div v-if="editing == 'girl.p2pd'" class="interval mw550">
          <Input type="textarea" :rows="10" v-model="texts[ 'girl.p2pd' ]" autofocus></Input>
          <div class="right top-interval">
            <el-button @click="editing = null">取消</el-button>
            &nbsp;&nbsp;
            <el-button @click="save_text( 'girl.p2pd' )" :loading="loadings[ 'save@girl.p2pd' ]" :disabled="is_locked">保存</el-button>
          </div>
        </div>
        <div v-else>
          <div v-html="texts[ 'girl.p2pd' ] ? texts[ 'girl.p2pd' ].replace( new RegExp( /\n/, 'g' ), '<br />' ) : ''"
            v-on:click="editing = 'girl.p2pd'"
            class="output mh200 output-area interval mw550"
          />
          <div v-if="saved == 'girl.p2pd'" class="mw550 right">
            <div> 配置生效需要重启{{ translates.p2p1_sshd }}，确认重启服务吗？ </div>
            <div class="top-interval">
              <el-button @click="saved = null">取消</el-button>
              &nbsp;&nbsp;
              <el-button @click="systemctl( 'restart', 'p2p1_sshd' )" :loading="loadings[ 'restart@p2p1_sshd' ]" :disabled="is_locked">重启{{ translates.p2p1_sshd }}</el-button>
            </div>
          </div>
        </div>
      </el-col>
      <el-col :span="1">&nbsp;</el-col>
    </el-row>

    <el-row>
      <el-col :span="1">&nbsp;</el-col>
      <el-col :span="22" id="footer">
        <div class="right">{{ measure_temp }}</div>
        <img id="shadow" src="./assets/shadow.jpg" />
        <div v-html="colour_actives.girla"></div>
      </el-col>
      <el-col :span="1">&nbsp;</el-col>
    </el-row>

  </div>
</template>

<script src="./app.js"></script>
