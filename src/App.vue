<template>
  <div id="app">

    <Row>
      <Col span="1">&nbsp;</Col>
      <Col span="22" id="header">
        <img id="bear" src="./assets/bear.jpg" />
        <div v-if="texts['girl.im']">{{ texts['girl.im'].trim() }}<span v-if="is_locked">&nbsp;<Icon type="md-lock" /></span></div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>
    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">妹子网关</div>
        <div class="interval">
          <span class="output" v-html="colour_actives.redir" v-on:click="show_redir_service"></span>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>
    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">妹子dns</div>
        <div class="interval">
          <span class="output" v-html="colour_actives.resolv" v-on:click="poppings[ 'service@resolv' ] = true"></span>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>
    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">sshd映射</div>
        <div class="interval">
          <span class="output" v-html="colour_actives.mirror_sshd" v-on:click="poppings[ 'service@mirror_sshd' ] = true"></span>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>
    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">热点</div>
        <div class="interval">
          <span class="output" v-html="colour_actives.hostapd" v-on:click="show_hostapd_service"></span>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>
    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">网卡</div>
        <div class="interval">
          <span class="output" v-html="colour_actives.dhcpcd" v-on:click="poppings[ 'service@dhcpcd' ] = true"></span>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>
    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">dhcp租约</div>
        <div class="interval">
          <span class="output" v-html="colour_actives.dnsmasq" v-on:click="poppings[ 'service@dnsmasq' ] = true"></span>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>
    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">网关远端地址</div>
        <div class="interval">
          <div class="output output-area mh200 mw512"
            v-html="texts[ 'girl.relayd' ] ? texts[ 'girl.relayd' ].replace(new RegExp(/\n/, 'g'), '<br />') : ''"
            v-on:click="poppings[ 'text@girl.relayd' ] = true">
          </div>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>
    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">dns远端地址</div>
        <div class="interval">
          <div class="output output-area mh200 mw512"
            v-html="texts[ 'girl.resolvd' ] ? texts[ 'girl.resolvd' ].replace(new RegExp(/\n/, 'g'), '<br />') : ''"
            v-on:click="poppings[ 'text@girl.resolvd' ] = true">
          </div>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>
    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">dns就近地址</div>
        <div class="interval">
          <div class="output output-area mh200 mw512"
            v-html="texts[ 'nameservers.txt' ] ? texts[ 'nameservers.txt' ].replace(new RegExp(/\n/, 'g'), '<br />') : ''"
            v-on:click="poppings[ 'text@nameservers.txt' ] = true">
          </div>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>
    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">sshd映射远端地址</div>
        <div class="interval">
          <div class="output output-area mh200 mw512"
            v-html="texts[ 'girl.mirrord' ] ? texts[ 'girl.mirrord' ].replace(new RegExp(/\n/, 'g'), '<br />') : ''"
            v-on:click="poppings[ 'text@girl.mirrord' ] = true">
          </div>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>
    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">自定义</div>
        <div class="interval">
          <div class="output output-area mh200 mw512"
            v-html="texts[ 'girl.custom.txt' ] ? texts[ 'girl.custom.txt' ].replace(new RegExp(/\n/, 'g'), '<br />') : ''"
            v-on:click="poppings[ 'text@girl.custom.txt' ] = true">
          </div>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>
    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">国内ip</div>
        <div class="interval">
          <div class="output output-area mh200 mw512"
            v-html="texts[ 'chnroute.txt' ] ? texts[ 'chnroute.txt' ].replace(new RegExp(/\n/, 'g'), '<br />') : ''"
            v-on:click="poppings[ 'text@chnroute.txt' ] = true">
          </div>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>
    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">热点配置</div>
        <div class="interval">
          <div class="output output-area mh200 mw512"
            v-html="texts[ 'hostapd.conf' ] ? texts[ 'hostapd.conf' ].replace(new RegExp(/\n/, 'g'), '<br />') : ''"
            v-on:click="poppings[ 'text@hostapd.conf' ] = true">
          </div>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>
    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">网卡配置</div>
        <div class="interval">
          <div class="output output-area mh200 mw512"
            v-html="texts[ 'dhcpcd.conf' ] ? texts[ 'dhcpcd.conf' ].replace(new RegExp(/\n/, 'g'), '<br />') : ''"
            v-on:click="poppings[ 'text@dhcpcd.conf' ] = true">
          </div>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>
    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">dhcp租约配置</div>
        <div class="interval">
          <div class="output output-area mh200 mw512"
            v-html="texts[ 'dnsmasq.d/wlan0.conf' ] ? texts[ 'dnsmasq.d/wlan0.conf' ].replace(new RegExp(/\n/, 'g'), '<br />') : ''"
            v-on:click="poppings[ 'text@dnsmasq.d/wlan0.conf' ] = true">
          </div>
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

    <Modal v-model="poppings[ 'service@redir' ]" title="妹子网关">
      <div class="row" v-html="colour_actives.redir"></div>
      <div v-html="expire_info" v-if="expire_info"></div>
      <p slot="footer" class="right">
        <Button @click="systemctl( 'stop', 'redir' )" :loading="loadings[ 'stop@redir' ]" v-if="runnings.redir" :disabled="is_locked">停止</Button>
        <Button @click="systemctl( 'start', 'redir' )" :loading="loadings[ 'start@redir' ]" v-if="!runnings.redir" :disabled="is_locked">启动</Button>
        <Button @click="systemctl( 'restart', 'redir' )" :loading="loadings[ 'restart@redir' ]" v-if="runnings.redir" :disabled="is_locked">重启</Button>
      </p>
    </Modal>

    <Modal v-model="poppings[ 'service@resolv' ]" title="妹子dns">
      <div class="row" v-html="colour_actives.resolv"></div>
      <p slot="footer">
        <Button @click="systemctl( 'stop', 'resolv' )" :loading="loadings[ 'stop@resolv' ]" v-if="runnings.resolv" :disabled="is_locked">停止</Button>
        <Button @click="systemctl( 'start', 'resolv' )" :loading="loadings[ 'start@resolv' ]" v-if="!runnings.resolv" :disabled="is_locked">启动</Button>
        <Button @click="systemctl( 'restart', 'resolv' )" :loading="loadings[ 'restart@resolv' ]" v-if="runnings.resolv" :disabled="is_locked">重启</Button>
      </p>
    </Modal>

    <Modal v-model="poppings[ 'service@mirror_sshd' ]" title="sshd映射">
      <div class="row" v-html="colour_actives.mirror_sshd"></div>
      <p slot="footer">
        <Checkbox v-model="enableds.mirror_sshd" @on-change="check_mirror_sshd" :disabled="is_locked">开机自动启动</Checkbox>
        <Button @click="systemctl( 'stop', 'mirror_sshd' )" :loading="loadings[ 'stop@mirror_sshd' ]" v-if="runnings.mirror_sshd" :disabled="is_locked">停止</Button>
        <Button @click="systemctl( 'start', 'mirror_sshd' )" :loading="loadings[ 'start@mirror_sshd' ]" v-if="!runnings.mirror_sshd" :disabled="is_locked">启动</Button>
        <Button @click="systemctl( 'restart', 'mirror_sshd' )" :loading="loadings[ 'restart@mirror_sshd' ]" v-if="runnings.mirror_sshd" :disabled="is_locked">重启</Button>
      </p>
    </Modal>

    <Modal v-model="poppings[ 'service@hostapd' ]" title="热点">
      <div class="row" v-html="colour_actives.hostapd"></div>
      <div class="output-area bottom-interval" v-html="connections_info" v-if="connections_info"></div>
      <p slot="footer">
        <Checkbox v-model="enableds.hostapd" @on-change="check_hostapd" :disabled="is_locked">开机自动启动</Checkbox>
        <Button @click="systemctl( 'stop', 'hostapd' )" :loading="loadings[ 'stop@hostapd' ]" v-if="runnings.hostapd" :disabled="is_locked">停止</Button>
        <Button @click="systemctl( 'start', 'hostapd' )" :loading="loadings[ 'start@hostapd' ]" v-if="!runnings.hostapd" :disabled="is_locked">启动</Button>
        <Button @click="systemctl( 'restart', 'hostapd' )" :loading="loadings[ 'restart@hostapd' ]" v-if="runnings.hostapd" :disabled="is_locked">重启</Button>
      </p>
    </Modal>

    <Modal v-model="poppings[ 'service@dhcpcd' ]" title="网卡">
      <div class="row" v-html="colour_actives.dhcpcd"></div>
      <p slot="footer">
        <Button @click="systemctl( 'restart', 'dhcpcd' )" :loading="loadings[ 'restart@dhcpcd' ]" :disabled="is_locked">重启</Button>
      </p>
    </Modal>

    <Modal v-model="poppings[ 'service@dnsmasq' ]" title="dhcp租约">
      <div class="row" v-html="colour_actives.dnsmasq"></div>
      <p slot="footer">
        <Button @click="systemctl( 'restart', 'dnsmasq' )" :loading="loadings[ 'restart@dnsmasq' ]" :disabled="is_locked">重启</Button>
      </p>
    </Modal>

    <Modal v-model="poppings[ 'text@girl.relayd' ]" title="编辑：网关远端地址">
      <Input type="textarea" :rows="10" v-model="texts[ 'girl.relayd' ]" autofocus></Input>
      <div class="right top-interval">
        <Alert type="error" v-if="error_on_saves[ 'girl.relayd' ]" class="interval">{{ error_on_saves[ 'girl.relayd' ] }}</Alert>
      </div>
      <p slot="footer">
        <Button @click="save_text( 'girl.relayd' )" :loading="loadings[ 'save@girl.relayd' ]" :disabled="is_locked">保存</Button>
      </p>
    </Modal>

    <Modal v-model="poppings[ 'text@girl.resolvd' ]" title="编辑：dns远端地址">
      <Input type="textarea" :rows="10" v-model="texts[ 'girl.resolvd' ]" autofocus></Input>
      <div class="right top-interval">
        <Alert type="error" v-if="error_on_saves[ 'girl.resolvd' ]" class="interval">{{ error_on_saves[ 'girl.resolvd' ] }}</Alert>
      </div>
      <p slot="footer">
        <Button @click="save_text( 'girl.resolvd' )" :loading="loadings[ 'save@girl.resolvd' ]" :disabled="is_locked">保存</Button>
      </p>
    </Modal>

    <Modal v-model="poppings[ 'text@nameservers.txt' ]" title="编辑：dns就近地址">
      <Input type="textarea" :rows="10" v-model="texts[ 'nameservers.txt' ]" autofocus></Input>
      <div class="right top-interval">
        <Alert type="error" v-if="error_on_saves[ 'nameservers.txt' ]" class="interval">{{ error_on_saves[ 'nameservers.txt' ] }}</Alert>
      </div>
      <p slot="footer">
        <Button @click="save_text( 'nameservers.txt' )" :loading="loadings[ 'save@nameservers.txt' ]" :disabled="is_locked">保存</Button>
      </p>
    </Modal>

    <Modal v-model="poppings[ 'text@girl.custom.txt' ]" title="编辑：自定义" :styles="{ top: '20px' }">
      <div class="bottom-interval">
        填写域名，该域名dns查询走妹子。例如：google.com<br />
        一行一个。<br />
        填写ip，该ip走妹子。例如：69.63.32.36<br />
        通常情况不需要填写ip，非国内ip自动走妹子。<br />
        前缀 “!” 表示忽略，不走妹子。例如：!69.63.32.36<br />
        “#” 接注释。例如：!69.63.32.36 # 忽略tasvideos
      </div>
      <Input type="textarea" :rows="20" v-model="texts[ 'girl.custom.txt' ]" autofocus></Input>
      <div class="right top-interval">
        <Alert type="error" v-if="error_on_saves[ 'girl.custom.txt' ]" class="interval">{{ error_on_saves[ 'girl.custom.txt' ] }}</Alert>
      </div>
      <p slot="footer">
        <Button @click="save_text( 'girl.custom.txt' )" :loading="loadings[ 'save@girl.custom.txt' ]" :disabled="is_locked">保存</Button>
      </p>
    </Modal>

    <Modal v-model="poppings[ 'text@hostapd.conf' ]" title="配置热点" :styles="{ top: '20px' }">
      <div class="bottom-interval">
        设置wifi名称，更改ssid行。例如：ssid=妹子<br />
        设置信道，更改channel行。例如：channel=11<br />
        设置wifi密码，更改wpa_passphrase行。例如：wpa_passphrase=lastcomm<br />
        设置是否隐藏，更改ignore_broadcast_ssid行。取值：0显示，1隐藏。例如：ignore_broadcast_ssid=1<br />
        设置5GHz wifi，更改hw_mode行：hw_mode=a，更改channel行：channel=36
      </div>
      <Input type="textarea" :rows="20" v-model="texts[ 'hostapd.conf' ]" autofocus></Input>
      <div class="right top-interval">
        <Alert type="error" v-if="error_on_saves[ 'hostapd.conf' ]" class="interval">{{ error_on_saves[ 'hostapd.conf' ] }}</Alert>
      </div>
      <p slot="footer">
        <Button @click="save_text( 'hostapd.conf' )" :loading="loadings[ 'save@hostapd.conf' ]" :disabled="is_locked">保存</Button>
      </p>
    </Modal>

    <Modal v-model="poppings[ 'text@dhcpcd.conf' ]" title="配置网卡">
      <Input type="textarea" :rows="10" v-model="texts[ 'dhcpcd.conf' ]" autofocus></Input>
      <div class="right top-interval">
        <Alert type="error" v-if="error_on_saves[ 'dhcpcd.conf' ]" class="interval">{{ error_on_saves[ 'dhcpcd.conf' ] }}</Alert>
      </div>
      <p slot="footer">
        <Button @click="save_text('dhcpcd.conf')" :loading="loadings[ 'save@dhcpcd.conf' ]" :disabled="is_locked">保存</Button>
      </p>
    </Modal>

    <Modal v-model="poppings[ 'text@dnsmasq.d/wlan0.conf' ]" title="配置dhcp租约">
      <Input type="textarea" :rows="10" v-model="texts[ 'dnsmasq.d/wlan0.conf' ]" autofocus></Input>
      <div class="right top-interval">
        <Alert type="error" v-if="error_on_saves[ 'dnsmasq.d/wlan0.conf' ]" class="interval">{{ error_on_saves[ 'dnsmasq.d/wlan0.conf' ] }}</Alert>
      </div>
      <p slot="footer">
        <Button @click="save_text('dnsmasq.d/wlan0.conf')" :loading="loadings[ 'save@dnsmasq.d/wlan0.conf' ]" :disabled="is_locked">保存</Button>
      </p>
    </Modal>

    <Modal v-model="poppings.exception" width="60" :styles="{ top: '20px', marginBottom: '20px' }">
      <p slot="header" style="color:#f60;text-align:center">
        <Icon type="ios-information-circle"></Icon>
        <span>{{ exception.title }}</span>
      </p>
      <div v-html="exception.message.replace(new RegExp(/\n/, 'g'), '<br />')"></div>
      <p slot="footer">
        <Button @click="poppings.exception = false">关闭</Button>
      </p>
    </Modal>

    <Modal v-model="poppings['saved@girl.relayd']" title="编辑网关远端地址成功">
      <p slot="footer"></p>
      <div> 配置生效需要重启妹子网关，确认重启服务吗？ </div>
      <div class="right top-interval">
        <Button @click="systemctl('restart', 'redir', 'saved@girl.relayd')" :loading="loadings[ 'restart@redir' ]" :disabled="is_locked">重启妹子网关</Button>
      </div>
    </Modal>

    <Modal v-model="poppings['saved@girl.resolvd']" title="编辑dns远端地址成功">
      <p slot="footer"></p>
      <div> 配置生效需要重启妹子dns，确认重启服务吗？ </div>
      <div class="right top-interval">
        <Button @click="systemctl('restart', 'resolv', 'saved@girl.resolvd')" :loading="loadings[ 'restart@resolv' ]" :disabled="is_locked">重启妹子dns</Button>
      </div>
    </Modal>

    <Modal v-model="poppings['saved@girl.mirror_sshd']" title="编辑sshd映射远端地址成功">
      <p slot="footer"></p>
      <div> 配置生效需要重启sshd映射，确认重启服务吗？ </div>
      <div class="right top-interval">
        <Button @click="systemctl('restart', 'mirror_sshd', 'saved@girl.mirror_sshd')" :loading="loadings[ 'restart@mirror_sshd' ]" :disabled="is_locked">重启sshd映射</Button>
      </div>
    </Modal>

    <Modal v-model="poppings['saved@hostapd.conf']" title="配置热点成功">
      <p slot="footer"></p>
      <div> 配置生效需要重启热点，确认重启服务吗？ </div>
      <div class="right top-interval">
        <Button @click="systemctl('restart', 'hostapd', 'saved@hostapd.conf')" :loading="loadings[ 'restart@hostapd' ]" :disabled="is_locked">重启热点</Button>
      </div>
    </Modal>

    <Modal v-model="poppings['saved@dhcpcd.conf']" title="配置网卡成功">
      <p slot="footer"></p>
      <div> 配置生效需要重启网卡，确认重启服务吗？ </div>
      <div class="right top-interval">
        <Button @click="systemctl('restart', 'dhcpcd', 'saved@dhcpcd.conf')" :loading="loadings[ 'restart@dhcpcd' ]" :disabled="is_locked">重启网卡</Button>
      </div>
    </Modal>

    <Modal v-model="poppings['saved@dnsmasq.d/wlan0.conf']" title="配置dhcp租约成功">
      <p slot="footer"></p>
      <div> 配置生效需要重启dhcp租约，确认重启服务吗？ </div>
      <div class="right top-interval">
        <Button @click="systemctl('restart', 'dnsmasq', 'saved@dnsmasq.d/wlan0.conf')" :loading="loadings[ 'restart@dnsmasq' ]" :disabled="is_locked">重启dhcp租约</Button>
      </div>
    </Modal>

  </div>
</template>

<script src="./app.js"></script>
