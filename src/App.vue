<template>
  <div id="app">

    <Row>
      <Col span="1">&nbsp;</Col>
      <Col span="22" id="header">
        <div><img id="bear" src="./assets/bear.jpg" /></div>
        <span v-if="is_locked">&nbsp;<Icon type="md-lock" /></span>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>
    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">{{ translates.redir }}</div>
        <div class="interval">
          <span class="output" v-html="colour_actives.redir" v-on:click="show_service( 'redir' )"></span>
        </div>
        <div v-if="editing == 'redir'" class="top-interval mw512">
          <div v-if="expire_info" v-html="expire_info"></div>
          <div class="top-interval right">
            <span>
              <Button @click="editing = null">取消</Button>
            </span>
            <span v-if="runnings.redir">
              &nbsp;&nbsp;
              <Button @click="systemctl( 'stop', 'redir' )" :loading="loadings[ 'stop@redir' ]" :disabled="is_locked">停止</Button>
            </span>
            <span v-if="!runnings.redir">
              &nbsp;&nbsp;
              <Button @click="systemctl( 'start', 'redir' )" :loading="loadings[ 'start@redir' ]" :disabled="is_locked">启动</Button>
            </span>
            <span v-if="runnings.redir">
              &nbsp;&nbsp;
              <Button @click="systemctl( 'restart', 'redir' )" :loading="loadings[ 'restart@redir' ]" :disabled="is_locked">重启</Button>
            </span>
          </div>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>
    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">{{ translates.resolv }}</div>
        <div class="interval">
          <span class="output" v-html="colour_actives.resolv" v-on:click="show_service( 'resolv' )"></span>
        </div>
        <div v-if="editing == 'resolv'" class="top-interval mw512">
          <div class="right">
            <span>
              <Button @click="editing = null">取消</Button>
            </span>
            <span v-if="runnings.resolv">
              &nbsp;&nbsp;
              <Button @click="systemctl( 'stop', 'resolv' )" :loading="loadings[ 'stop@resolv' ]" :disabled="is_locked">停止</Button>
            </span>
            <span v-if="!runnings.resolv">
              &nbsp;&nbsp;
              <Button @click="systemctl( 'start', 'resolv' )" :loading="loadings[ 'start@resolv' ]" :disabled="is_locked">启动</Button>
            </span>
            <span v-if="runnings.resolv">
              &nbsp;&nbsp;
              <Button @click="systemctl( 'restart', 'resolv' )" :loading="loadings[ 'restart@resolv' ]" :disabled="is_locked">重启</Button>
            </span>
          </div>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>
    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">{{ translates.hostapd }}</div>
        <div class="interval">
          <span class="output" v-html="colour_actives.hostapd" v-on:click="show_service( 'hostapd' )"></span>
        </div>
        <div v-if="editing == 'hostapd'" class="top-interval mw512">
          <div class="right">
            <span>
              <Checkbox v-model="enableds.hostapd" @on-change="check_hostapd" :disabled="is_locked">开机自动启动</Checkbox>
            </span>
            <span>
              &nbsp;&nbsp;
              <Button @click="editing = null">取消</Button>
            </span>
            <span v-if="runnings.hostapd">
              &nbsp;&nbsp;
              <Button @click="systemctl( 'stop', 'hostapd' )" :loading="loadings[ 'stop@hostapd' ]" :disabled="is_locked">停止</Button>
            </span>
            <span v-if="!runnings.hostapd">
              &nbsp;&nbsp;
              <Button @click="systemctl( 'start', 'hostapd' )" :loading="loadings[ 'start@hostapd' ]" :disabled="is_locked">启动</Button>
            </span>
            <span v-if="runnings.hostapd">
              &nbsp;&nbsp;
              <Button @click="systemctl( 'restart', 'hostapd' )" :loading="loadings[ 'restart@hostapd' ]" :disabled="is_locked">重启</Button>
            </span>
          </div>
          <div class="top-interval output-area" v-html="connections_info" v-if="connections_info"></div>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>
    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">{{ translates.dhcpcd }}</div>
        <div class="interval">
          <span class="output" v-html="colour_actives.dhcpcd" v-on:click="show_service( 'dhcpcd' )"></span>
        </div>
        <div v-if="editing == 'dhcpcd'" class="top-interval mw512">
          <div class="right">
            <span>
              <Button @click="editing = null">取消</Button>
            </span>
            <span v-if="runnings.dhcpcd">
              &nbsp;&nbsp;
              <Button @click="systemctl( 'restart', 'dhcpcd' )" :loading="loadings[ 'restart@dhcpcd' ]" :disabled="is_locked">重启</Button>
            </span>
          </div>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>
    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">{{ translates.dnsmasq }}</div>
        <div class="interval">
          <span class="output" v-html="colour_actives.dnsmasq" v-on:click="show_service( 'dnsmasq' )"></span>
        </div>
        <div v-if="editing == 'dnsmasq'" class="top-interval mw512">
          <div class="right">
            <span>
              <Button @click="editing = null">取消</Button>
            </span>
            <span v-if="runnings.dnsmasq">
              &nbsp;&nbsp;
              <Button @click="systemctl( 'restart', 'dnsmasq' )" :loading="loadings[ 'restart@dnsmasq' ]" :disabled="is_locked">重启</Button>
            </span>
          </div>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>
    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">{{ translates.p2p1_sshd }}</div>
        <div class="interval">
          <span class="output" v-html="colour_actives.p2p1_sshd" v-on:click="show_service( 'p2p1_sshd' )"></span>
        </div>
        <div v-if="editing == 'p2p1_sshd'" class="top-interval mw512">
          <div class="right">
            <span>
              <Checkbox v-model="enableds.p2p1_sshd" @on-change="check_p2p1_sshd" :disabled="is_locked">开机自动启动</Checkbox>
            </span>
            <span>
              &nbsp;&nbsp;
              <Button @click="editing = null">取消</Button>
            </span>
            <span v-if="runnings.p2p1_sshd">
              &nbsp;&nbsp;
              <Button @click="systemctl( 'stop', 'p2p1_sshd' )" :loading="loadings[ 'stop@p2p1_sshd' ]" :disabled="is_locked">停止</Button>
            </span>
            <span v-if="!runnings.p2p1_sshd">
              &nbsp;&nbsp;
              <Button @click="systemctl( 'start', 'p2p1_sshd' )" :loading="loadings[ 'start@p2p1_sshd' ]" :disabled="is_locked">启动</Button>
            </span>
            <span v-if="runnings.p2p1_sshd">
              &nbsp;&nbsp;
              <Button @click="systemctl( 'restart', 'p2p1_sshd' )" :loading="loadings[ 'restart@p2p1_sshd' ]" :disabled="is_locked">重启</Button>
            </span>
          </div>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>

    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">{{ translates[ 'girl.relayd' ] }}</div>
        <div v-if="editing == 'girl.relayd'" class="interval mw512">
          <Input type="textarea" :rows="10" v-model="texts[ 'girl.relayd' ]" autofocus></Input>
          <div class="right top-interval">
            <Button @click="editing = null">取消</Button>
            &nbsp;&nbsp;
            <Button @click="save_text( 'girl.relayd' )" :loading="loadings[ 'save@girl.relayd' ]" :disabled="is_locked">保存</Button>
          </div>
        </div>
        <div v-else
          class="output mh200 output-area interval mw512"
          v-html="texts[ 'girl.relayd' ] ? texts[ 'girl.relayd' ].replace(new RegExp(/\n/, 'g'), '<br />') : ''"
          v-on:click="editing = 'girl.relayd'">
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>
    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">{{ translates[ 'girl.resolvd' ] }}</div>
        <div v-if="editing == 'girl.resolvd'" class="interval mw512">
          <Input type="textarea" :rows="10" v-model="texts[ 'girl.resolvd' ]" autofocus></Input>
          <div class="right top-interval">
            <Button @click="editing = null">取消</Button>
            &nbsp;&nbsp;
            <Button @click="save_text( 'girl.resolvd' )" :loading="loadings[ 'save@girl.resolvd' ]" :disabled="is_locked">保存</Button>
          </div>
        </div>
        <div v-else
          class="output mh200 output-area interval mw512"
          v-html="texts[ 'girl.resolvd' ] ? texts[ 'girl.resolvd' ].replace(new RegExp(/\n/, 'g'), '<br />') : ''"
          v-on:click="editing = 'girl.resolvd'">
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>
    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">{{ translates[ 'nameservers.txt' ] }}</div>
        <div v-if="editing == 'nameservers.txt'" class="interval mw512">
          <Input type="textarea" :rows="10" v-model="texts[ 'nameservers.txt' ]" autofocus></Input>
          <div class="right top-interval">
            <Button @click="editing = null">取消</Button>
            &nbsp;&nbsp;
            <Button @click="save_text( 'nameservers.txt' )" :loading="loadings[ 'save@nameservers.txt' ]" :disabled="is_locked">保存</Button>
          </div>
        </div>
        <div v-else
          class="output mh200 output-area interval mw512"
          v-html="texts[ 'nameservers.txt' ] ? texts[ 'nameservers.txt' ].replace(new RegExp(/\n/, 'g'), '<br />') : ''"
          v-on:click="editing = 'nameservers.txt'">
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>
    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">{{ translates[ 'girl.custom.txt' ] }}</div>
        <div v-if="editing == 'girl.custom.txt'" class="interval mw512">
          <Input type="textarea" :rows="10" v-model="texts[ 'girl.custom.txt' ]" autofocus></Input>
          <div class="right top-interval">
            <Button @click="editing = null">取消</Button>
            &nbsp;&nbsp;
            <Button @click="save_text( 'girl.custom.txt' )" :loading="loadings[ 'save@girl.custom.txt' ]" :disabled="is_locked">保存</Button>
          </div>
          <div class="top-interval">
            填写域名，该域名dns查询走妹子。例如：google.com<br />
            一行一个。<br />
            填写ip，该ip走妹子。例如：69.63.32.36<br />
            通常情况不需要填写ip，<a target="_blank" :href="http_host + '/chnroute.txt'">国内ip段</a>之外的ip默认走妹子。<br />
            前缀 “!” 表示忽略，不走妹子。例如：!69.63.32.36<br />
            “#” 接注释。例如：!69.63.32.36 # 忽略tasvideos
          </div>
        </div>
        <div v-else
          class="output mh200 output-area interval mw512"
          v-html="texts[ 'girl.custom.txt' ] ? texts[ 'girl.custom.txt' ].replace(new RegExp(/\n/, 'g'), '<br />') : ''"
          v-on:click="editing = 'girl.custom.txt'">
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>
    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">{{ translates[ 'hostapd.conf' ] }}</div>
        <div v-if="editing == 'hostapd.conf'" class="interval mw512">
          <Input type="textarea" :rows="10" v-model="texts[ 'hostapd.conf' ]" autofocus></Input>
          <div class="right top-interval">
            <Button @click="editing = null">取消</Button>
            &nbsp;&nbsp;
            <Button @click="save_text( 'hostapd.conf' )" :loading="loadings[ 'save@hostapd.conf' ]" :disabled="is_locked">保存</Button>
          </div>
          <div class="top-interval">
            设置wifi名称，更改 ssid 行。<br />
            设置信道，更改 channel 行。<br />
            设置wifi密码，更改 wpa_passphrase 行。<br />
            设置是否隐藏，更改 ignore_broadcast_ssid 行。取值：0显示，1隐藏。
          </div>
        </div>
        <div v-else
          class="output mh200 output-area interval mw512"
          v-html="texts[ 'hostapd.conf' ] ? texts[ 'hostapd.conf' ].replace(new RegExp(/\n/, 'g'), '<br />') : ''"
          v-on:click="editing = 'hostapd.conf'">
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>
    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">{{ translates[ 'dhcpcd.conf' ] }}</div>
        <div v-if="editing == 'dhcpcd.conf'" class="interval mw512">
          <Input type="textarea" :rows="10" v-model="texts[ 'dhcpcd.conf' ]" autofocus></Input>
          <div class="right top-interval">
            <Button @click="editing = null">取消</Button>
            &nbsp;&nbsp;
            <Button @click="save_text( 'dhcpcd.conf' )" :loading="loadings[ 'save@dhcpcd.conf' ]" :disabled="is_locked">保存</Button>
          </div>
        </div>
        <div v-else
          class="output mh200 output-area interval mw512"
          v-html="texts[ 'dhcpcd.conf' ] ? texts[ 'dhcpcd.conf' ].replace(new RegExp(/\n/, 'g'), '<br />') : ''"
          v-on:click="editing = 'dhcpcd.conf'">
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>
    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">{{ translates[ 'dnsmasq.d/wlan0.conf' ] }}</div>
        <div v-if="editing == 'dnsmasq.d/wlan0.conf'" class="interval mw512">
          <Input type="textarea" :rows="10" v-model="texts[ 'dnsmasq.d/wlan0.conf' ]" autofocus></Input>
          <div class="right top-interval">
            <Button @click="editing = null">取消</Button>
            &nbsp;&nbsp;
            <Button @click="save_text( 'dnsmasq.d/wlan0.conf' )" :loading="loadings[ 'save@dnsmasq.d/wlan0.conf' ]" :disabled="is_locked">保存</Button>
          </div>
        </div>
        <div v-else
          class="output mh200 output-area interval mw512"
          v-html="texts[ 'dnsmasq.d/wlan0.conf' ] ? texts[ 'dnsmasq.d/wlan0.conf' ].replace(new RegExp(/\n/, 'g'), '<br />') : ''"
          v-on:click="editing = 'dnsmasq.d/wlan0.conf'">
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>
    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">{{ translates[ 'girl.p2pd' ] }}</div>
        <div v-if="editing == 'girl.p2pd'" class="interval mw512">
          <Input type="textarea" :rows="10" v-model="texts[ 'girl.p2pd' ]" autofocus></Input>
          <div class="right top-interval">
            <Button @click="editing = null">取消</Button>
            &nbsp;&nbsp;
            <Button @click="save_text( 'girl.p2pd' )" :loading="loadings[ 'save@girl.p2pd' ]" :disabled="is_locked">保存</Button>
          </div>
        </div>
        <div v-else
          class="output mh200 output-area interval mw512"
          v-html="texts[ 'girl.p2pd' ] ? texts[ 'girl.p2pd' ].replace(new RegExp(/\n/, 'g'), '<br />') : ''"
          v-on:click="editing = 'girl.p2pd'">
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>
    <Row>
      <Col span="1">&nbsp;</Col>
      <Col span="22" id="footer">
        <div class="right">{{ measure_temp }}</div>
        <img id="shadow" src="./assets/shadow.jpg" />
        <div v-html="colour_actives.girla"></div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>

    <Modal v-model="poppings.exception" width="60" :styles="{ top: '20px', marginBottom: '20px' }">
      <p slot="header" style="color:#f60; text-align:center;">
        <Icon type="ios-information-circle"></Icon>
        <span>{{ exception.title }}</span>
      </p>
      <div v-html="exception.message.replace(new RegExp(/\n/, 'g'), '<br />')"></div>
      <p slot="footer">
        <Button @click="poppings.exception = false">关闭</Button>
      </p>
    </Modal>

    <Modal v-model="poppings['saved@girl.relayd']" :title="'编辑' + translates[ 'girl.relayd' ] + '成功'">
      <div> 配置生效需要重启{{ translates.redir }}，确认重启服务吗？ </div>
      <p slot="footer">
        <div class="right top-interval">
          <Button @click="systemctl('restart', 'redir', 'saved@girl.relayd')" :loading="loadings[ 'restart@redir' ]" :disabled="is_locked">重启{{ translates.redir }}</Button>
        </div>
      </p>
    </Modal>

    <Modal v-model="poppings['saved@girl.resolvd']" :title="'编辑' + translates[ 'girl.resolvd' ] + '成功'">
      <div> 配置生效需要重启{{ translates.resolv }}，确认重启服务吗？ </div>
      <p slot="footer">
        <div class="right top-interval">
          <Button @click="systemctl('restart', 'resolv', 'saved@girl.resolvd')" :loading="loadings[ 'restart@resolv' ]" :disabled="is_locked">重启{{ translates.resolv }}</Button>
        </div>
      </p>
    </Modal>

    <Modal v-model="poppings['saved@girl.p2pd']" :title="'编辑' + translates[ 'girl.p2pd' ] + '成功'">
      <div> 配置生效需要重启{{ translates.p2p1_sshd }}，确认重启服务吗？ </div>
      <p slot="footer">
        <div class="right top-interval">
          <Button @click="systemctl('restart', 'p2p1_sshd', 'saved@girl.p2pd')" :loading="loadings[ 'restart@p2p1_sshd' ]" :disabled="is_locked">重启{{ translates.p2p1_sshd }}</Button>
        </div>
      </p>
    </Modal>

    <Modal v-model="poppings['saved@hostapd.conf']" :title="'编辑' + translates[ 'hostapd.conf' ] + '成功'">
      <div> 配置生效需要重启{{ translates.hostapd }}，确认重启服务吗？ </div>
      <p slot="footer">
        <div class="right top-interval">
          <Button @click="systemctl('restart', 'hostapd', 'saved@hostapd.conf')" :loading="loadings[ 'restart@hostapd' ]" :disabled="is_locked">重启{{ translates.hostapd }}</Button>
        </div>
      </p>
    </Modal>

    <Modal v-model="poppings['saved@dhcpcd.conf']" :title="'编辑' + translates[ 'dhcpcd.conf' ] + '成功'">
      <div> 配置生效需要重启{{ translates.dhcpcd }}，确认重启服务吗？ </div>
      <p slot="footer">
        <div class="right top-interval">
          <Button @click="systemctl('restart', 'dhcpcd', 'saved@dhcpcd.conf')" :loading="loadings[ 'restart@dhcpcd' ]" :disabled="is_locked">重启{{ translates.dhcpcd }}</Button>
        </div>
      </p>
    </Modal>

    <Modal v-model="poppings['saved@dnsmasq.d/wlan0.conf']" :title="'编辑' + translates[ 'dnsmasq.d/wlan0.conf' ] + '成功'">
      <div> 配置生效需要重启{{ translates.dnsmasq }}，确认重启服务吗？ </div>
      <p slot="footer">
        <div class="right top-interval">
          <Button @click="systemctl('restart', 'dnsmasq', 'saved@dnsmasq.d/wlan0.conf')" :loading="loadings[ 'restart@dnsmasq' ]" :disabled="is_locked">重启{{ translates.dnsmasq }}</Button>
        </div>
      </p>
    </Modal>

  </div>
</template>

<script src="./app.js"></script>
