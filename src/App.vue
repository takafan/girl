<template>
  <div id="app">

    <Row>
      <Col span="1">&nbsp;</Col>
      <Col span="22" id="header">
        <span class="title">最终路由器彼女 ~</span>
        <span>{{ data.im }}</span>
        <img id="bear" src="./assets/bear.jpg" />
        <div v-if="data.is_locked"><Icon type="locked"></Icon></div>
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
        <div class="title bold">网卡</div>
        <div class="interval">
          <span class="output" v-html="colour_actives.networking" v-on:click="poppings[ 'service@networking' ] = true"></span>
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
        <div class="title bold">网关远端地址</div>
        <div class="interval">
          <div class="output output-area mh200 mw512"
            v-html="data.texts[ 'girl.relayd' ] ? data.texts[ 'girl.relayd' ].replace(new RegExp(/\n/, 'g'), '<br />') : ''"
            v-on:click="poppings[ 'text@redir' ] = true">
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
            v-html="data.texts[ 'girl.resolvd' ] ? data.texts[ 'girl.resolvd' ].replace(new RegExp(/\n/, 'g'), '<br />') : ''"
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
            v-html="data.texts[ 'nameservers.txt' ] ? data.texts[ 'nameservers.txt' ].replace(new RegExp(/\n/, 'g'), '<br />') : ''"
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
            v-html="data.texts[ 'girl.mirrord' ] ? data.texts[ 'girl.mirrord' ].replace(new RegExp(/\n/, 'g'), '<br />') : ''"
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
            v-html="data.texts[ 'girl.custom.txt' ] ? data.texts[ 'girl.custom.txt' ].replace(new RegExp(/\n/, 'g'), '<br />') : ''"
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
            v-html="data.texts[ 'chnroute.txt' ] ? data.texts[ 'chnroute.txt' ].replace(new RegExp(/\n/, 'g'), '<br />') : ''"
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
            v-html="data.texts[ 'hostapd.conf' ] ? data.texts[ 'hostapd.conf' ].replace(new RegExp(/\n/, 'g'), '<br />') : ''"
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
            v-html="data.texts[ 'interfaces.d/br0.cfg' ] ? data.texts[ 'interfaces.d/br0.cfg' ].replace(new RegExp(/\n/, 'g'), '<br />') : ''"
            v-on:click="poppings[ 'text@interfaces.d/br0.cfg' ] = true">
          </div>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>
    <Row>
      <Col span="1">&nbsp;</Col>
      <Col span="22" id="footer">
        <div class="right">{{ data.measure_temp }}</div>
        <img id="shadow" src="./assets/shadow.jpg" />
        <div v-html="colour_actives.girla"></div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>

    <Modal v-model="poppings[ 'service@redir' ]" title="妹子网关">
      <div class="row" v-html="colour_actives.redir"></div>
      <div v-html="expire_info" v-if="expire_info"></div>
      <p slot="footer" class="right">
        <Button @click="systemctl( 'stop', 'redir' )" :loading="loadings[ 'stop@redir' ]" v-if="runnings.redir" :disabled="data.is_locked">停止</Button>
        <Button @click="systemctl( 'start', 'redir' )" :loading="loadings[ 'start@redir' ]" v-if="!runnings.redir" :disabled="data.is_locked">启动</Button>
        <Button @click="systemctl( 'restart', 'redir' )" :loading="loadings[ 'restart@redir' ]" v-if="runnings.redir" :disabled="data.is_locked">重启</Button>
      </p>
    </Modal>

    <Modal v-model="poppings[ 'service@resolv' ]" title="妹子dns">
      <div class="row" v-html="colour_actives.resolv"></div>
      <p slot="footer">
        <Button @click="systemctl( 'stop', 'resolv' )" :loading="loadings[ 'stop@resolv' ]" v-if="runnings.resolv" :disabled="data.is_locked">停止</Button>
        <Button @click="systemctl( 'start', 'resolv' )" :loading="loadings[ 'start@resolv' ]" v-if="!runnings.resolv" :disabled="data.is_locked">启动</Button>
        <Button @click="systemctl( 'restart', 'resolv' )" :loading="loadings[ 'restart@resolv' ]" v-if="runnings.resolv" :disabled="data.is_locked">重启</Button>
      </p>
    </Modal>

    <Modal v-model="poppings[ 'service@mirror_sshd' ]" title="sshd映射">
      <div class="row" v-html="colour_actives.mirror_sshd"></div>
      <p slot="footer">
        <Button @click="systemctl( 'stop', 'mirror_sshd' )" :loading="loadings[ 'stop@mirror_sshd' ]" v-if="runnings.mirror_sshd" :disabled="data.is_locked">停止</Button>
        <Button @click="systemctl( 'start', 'mirror_sshd' )" :loading="loadings[ 'start@mirror_sshd' ]" v-if="!runnings.mirror_sshd" :disabled="data.is_locked">启动</Button>
        <Button @click="systemctl( 'restart', 'mirror_sshd' )" :loading="loadings[ 'restart@mirror_sshd' ]" v-if="runnings.mirror_sshd" :disabled="data.is_locked">重启</Button>
      </p>
    </Modal>

    <Modal v-model="poppings[ 'service@networking' ]" title="网卡">
      <div class="row" v-html="colour_actives.networking"></div>
      <p slot="footer">
        <Button @click="systemctl( 'restart', 'networking' )" :loading="loadings[ 'restart@networking' ]" :disabled="data.is_locked">重启</Button>
      </p>
    </Modal>

    <Modal v-model="poppings[ 'service@hostapd' ]" title="热点">
      <div class="row" v-html="colour_actives.hostapd"></div>
      <div class="output-area bottom-interval" v-html="connections_info" v-if="connections_info"></div>
      <p slot="footer">
        <Checkbox v-model="enableds.hostapd" @on-change="check_hostapd" :disabled="data.is_locked">开机自动启动</Checkbox>
        <Button @click="systemctl( 'stop', 'hostapd' )" :loading="loadings[ 'stop@hostapd' ]" v-if="runnings.hostapd" :disabled="data.is_locked">停止</Button>
        <Button @click="systemctl( 'start', 'hostapd' )" :loading="loadings[ 'start@hostapd' ]" v-if="!runnings.hostapd" :disabled="data.is_locked">启动</Button>
        <Button @click="systemctl( 'restart', 'hostapd' )" :loading="loadings[ 'restart@hostapd' ]" v-if="runnings.hostapd" :disabled="data.is_locked">重启</Button>
      </p>
    </Modal>

    <Modal v-model="poppings[ 'text@girl.relayd' ]" title="编辑：网关远端地址">
      <Input type="textarea" :rows="10" v-model="data.texts[ 'girl.relayd' ]" autofocus></Input>
      <div class="right top-interval">
        <Alert type="error" v-if="error_on_saves[ 'girl.relayd' ]" class="interval">{{ error_on_saves[ 'girl.relayd' ] }}</Alert>
      </div>
      <p slot="footer">
        <Button @click="save_text( 'girl.relayd' )" :loading="loadings[ 'save@girl.relayd' ]" :disabled="data.is_locked">保存</Button>
      </p>
    </Modal>

    <Modal v-model="poppings[ 'text@girl.resolvd' ]" title="编辑：dns远端地址">
      <Input type="textarea" :rows="10" v-model="data.texts[ 'girl.resolvd' ]" autofocus></Input>
      <div class="right top-interval">
        <Alert type="error" v-if="error_on_saves[ 'girl.resolvd' ]" class="interval">{{ error_on_saves[ 'girl.resolvd' ] }}</Alert>
      </div>
      <p slot="footer">
        <Button @click="save_text( 'girl.resolvd' )" :loading="loadings[ 'save@girl.resolvd' ]" :disabled="data.is_locked">保存</Button>
      </p>
    </Modal>

    <Modal v-model="poppings[ 'text@nameservers.txt' ]" title="编辑：dns就近地址">
      <Input type="textarea" :rows="10" v-model="data.texts[ 'nameservers.txt' ]" autofocus></Input>
      <div class="right top-interval">
        <Alert type="error" v-if="error_on_saves[ 'nameservers.txt' ]" class="interval">{{ error_on_saves[ 'nameservers.txt' ] }}</Alert>
      </div>
      <p slot="footer">
        <Button @click="save_text( 'nameservers.txt' )" :loading="loadings[ 'save@nameservers.txt' ]" :disabled="data.is_locked">保存</Button>
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
      <Input type="textarea" :rows="20" v-model="data.texts[ 'girl.custom.txt' ]" autofocus></Input>
      <div class="right top-interval">
        <Alert type="error" v-if="error_on_saves[ 'girl.custom.txt' ]" class="interval">{{ error_on_saves[ 'girl.custom.txt' ] }}</Alert>
      </div>
      <p slot="footer">
        <Button @click="save_text( 'girl.custom.txt' )" :loading="loadings[ 'save@girl.custom.txt' ]" :disabled="data.is_locked">保存</Button>
      </p>
    </Modal>

    <Modal v-model="poppings[ 'text@interfaces.d/eth0.cfg' ]" title="配置网卡">
      <div class="bottom-interval">
        设置妹子的内网ip，更改address行。<br />
        若要指定物理地址，添加行： hwaddress ether a1:b2:c3:d4:e5:f6
      </div>
      <Input type="textarea" :rows="10" v-model="data.texts[ 'interfaces.d/eth0.cfg' ]" autofocus></Input>
      <div class="right top-interval">
        <Alert type="error" v-if="error_on_saves[ 'interfaces.d/eth0.cfg' ]" class="interval">{{ error_on_saves[ 'interfaces.d/eth0.cfg' ] }}</Alert>
      </div>
      <p slot="footer">
        <Button @click="save_text('br0_text')" :loading="loadings[ 'save@interfaces.d/eth0.cfg' ]" :disabled="data.is_locked">保存</Button>
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
      <Input type="textarea" :rows="20" v-model="data.texts[ 'hostapd.conf' ]" autofocus></Input>
      <div class="right top-interval">
        <Alert type="error" v-if="error_on_saves[ 'hostapd.conf' ]" class="interval">{{ error_on_saves[ 'hostapd.conf' ] }}</Alert>
      </div>
      <p slot="footer">
        <Button @click="save_text( 'hostapd.conf' )" :loading="loadings[ 'save@hostapd.conf' ]" :disabled="data.is_locked">保存</Button>
      </p>
    </Modal>

    <Modal v-model="modals.exception" :title="exception.title" width="60" :styles="{ top: '20px', marginBottom: '20px' }">
      <p slot="footer">
        <Button @click="modals.exception = false">关闭</Button>
      </p>

      <div v-html="exception.message.replace(new RegExp(/\n/, 'g'), '<br />')"></div>
    </Modal>

    <Modal v-model="modals.need_restart_redir" title="编辑girl.relay成功">
      <p slot="footer"></p>
      <div> 配置生效需要重启redir，确认重启redir吗？ </div>
      <div class="right top-interval">
        <Button @click="systemctl('restart', 'redir', 'need_restart_redir')" :loading="loading.restart_redir" :disabled="data.is_locked">重启redir</Button>
      </div>
    </Modal>

    <Modal v-model="modals.need_restart_dnsmasq" :title="modal_titles.need_restart_dnsmasq">
      <p slot="footer"></p>
      <div> 配置生效需要重启dnsmasq，确认重启dnsmasq吗？ </div>
      <div class="right top-interval">
        <Button @click="systemctl('restart', 'dnsmasq', 'need_restart_dnsmasq')" :loading="loading.restart_dnsmasq" :disabled="data.is_locked">重启dnsmasq</Button>
      </div>
    </Modal>

    <Modal v-model="modals.need_restart_hostapd" title="编辑hostapd.conf成功">
      <p slot="footer"></p>
      <div> 配置生效需要重启hostapd，确认重启hostapd吗？ </div>
      <div class="right top-interval">
        <Button @click="systemctl('restart', 'hostapd', 'need_restart_hostapd')" :loading="loading.restart_hostapd" :disabled="data.is_locked">重启hostapd</Button>
      </div>
    </Modal>

    <Modal v-model="modals.need_restart_networking" title="编辑br0.cfg成功">
      <p slot="footer"></p>
      <div> 配置生效需要重启networking，确认重启networking吗？ </div>
      <div class="right top-interval">
        <Button @click="systemctl('restart', 'networking', 'need_restart_networking')" :loading="loading.restart_networking" :disabled="data.is_locked">重启networking</Button>
      </div>
    </Modal>
  </div>
</template>

<script src="./app.js"></script>
