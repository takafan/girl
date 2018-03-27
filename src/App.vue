<template>
  <div id="app">

    <Row>
      <Col span="1">&nbsp;</Col>
      <Col span="22" id="header">
        <span class="title">最终路由器彼女 ~</span>
        <img id="bear" src="./assets/bear.jpg" />
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>

    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">redir</div>
        <div class="interval">
          <span class="output" v-html="data.redir_active" v-on:click="show_redir_service"></span>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>

    <Modal v-model="modals.redir_service" title="redir服务">
      <p slot="footer"></p>
      <div class="bottom-interval">
        妹子绕道服务，通常出国走妹子绕道比电信/移动出去快，所以也可以看成加速服务。
      </div>
      <div class="row" v-html="data.redir_active"></div>
      <div v-html="expire_info" v-if="expire_info"></div>
      <div class="right">
        <Button @click="systemctl('stop', 'redir', 'redir_service')" :loading="loading.stop_redir" v-if="data.redir_running">停止</Button>
        <Button @click="systemctl('start', 'redir', 'redir_service')" :loading="loading.start_redir" v-if="!data.redir_running">启动</Button>
        <Button @click="systemctl('restart', 'redir', 'redir_service')" :loading="loading.restart_redir" v-if="data.redir_running">重启</Button>
      </div>
    </Modal>

    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">dnsmasq</div>
        <div class="interval">
          <span class="output" v-html="data.dnsmasq_active" v-on:click="modals.dnsmasq_service = true"></span>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>

    <Modal v-model="modals.dnsmasq_service" title="dnsmasq服务">
      <p slot="footer"></p>
      <div class="row" v-html="data.dnsmasq_active"></div>
      <div class="right">

        <Button @click="systemctl('stop', 'dnsmasq', 'dnsmasq_service')" :loading="loading.stop_dnsmasq" v-if="data.dnsmasq_running">停止</Button>
        <Button @click="systemctl('start', 'dnsmasq', 'dnsmasq_service')" :loading="loading.start_dnsmasq" v-if="!data.dnsmasq_running">启动</Button>
        <Button @click="systemctl('restart', 'dnsmasq', 'dnsmasq_service')" :loading="loading.restart_dnsmasq" v-if="data.dnsmasq_running">重启</Button>
      </div>
    </Modal>

    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">networking</div>
        <div class="interval">
          <span class="output" v-html="data.networking_active" v-on:click="modals.networking_service = true"></span>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>

    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">hostapd</div>
        <div class="interval">
          <span class="output" v-html="data.hostapd_active" v-on:click="show_hostapd_service"></span>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>

    <Modal v-model="modals.networking_service" title="networking服务">
      <p slot="footer"></p>
      <div class="row" v-html="data.networking_active"></div>
      <div class="right">
        <Button @click="systemctl('restart', 'networking', 'networking_service')" :loading="loading.restart_networking">重启</Button>
      </div>
    </Modal>

    <Modal v-model="modals.hostapd_service" title="hostapd服务" :styles="{ top: '20px' }">
      <p slot="footer"></p>
      <div class="row" v-html="data.hostapd_active"></div>
      <div class="output-area mh400 bottom-interval"
           v-html="connections_info" v-if="connections_info">
      </div>
      <div class="right">
        <Checkbox v-model="data.hostapd_enabled" @on-change="check_hostapd">开机自动启动</Checkbox>
        <Button @click="systemctl('stop', 'hostapd', 'hostapd_service')" :loading="loading.stop_hostapd" v-if="data.hostapd_running">停止</Button>
        <Button @click="systemctl('start', 'hostapd', 'hostapd_service')" :loading="loading.start_hostapd" v-if="!data.hostapd_running">启动</Button>
        <Button @click="systemctl('restart', 'hostapd', 'hostapd_service')" :loading="loading.restart_hostapd" v-if="data.hostapd_running">重启</Button>
      </div>
    </Modal>

    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">远程地址</div>
        <div class="interval">
          <div class="output output-area mh200 mw512"
            v-html="data.relay_text ? data.relay_text.replace(new RegExp(/\n/, 'g'), '<br />') : ''"
            v-on:click="modals.relay_text = true">
          </div>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>

    <Modal v-model="modals.relay_text" title="编辑远程地址">
      <p slot="footer"></p>
      <Input type="textarea" :rows="10" v-model="data.relay_text" autofocus></Input>
      <div class="right top-interval">
        <Alert type="error" v-if="error_on_save.relay_text" class="interval">{{ error_on_save.relay_text }}</Alert>
        <Button @click="save_text('relay_text')" :loading="loading.save_relay_text">保存</Button>
      </div>
    </Modal>

    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">自定义</div>
        <div class="interval">
          <div class="output output-area mh200 mw512"
            v-html="data.custom_text ? data.custom_text.replace(new RegExp(/\n/, 'g'), '<br />') : ''"
            v-on:click="modals.custom_text = true"
            :loading="loading.save_custom_text">
          </div>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>

    <Modal v-model="modals.custom_text" title="编辑自定义" :styles="{ top: '20px' }">
      <p slot="footer"></p>
      <div class="bottom-interval">
        填写域名，该域名dns查询走妹子。例如：google.com<br />
        一行一个。<br />
        填写ip，该ip走妹子。例如：69.63.32.36<br />
        通常情况不需要填写ip，妹子会自动识别国外ip绕道。<br />
        前缀 “!” 表示忽略，不走妹子。例如：!69.63.32.36<br />
        “#” 接注释。例如：!69.63.32.36 # 忽略tasvideos
      </div>
      <Input type="textarea" :rows="20" v-model="data.custom_text" autofocus></Input>
      <div class="right top-interval">
        <Alert type="error" v-if="error_on_save.custom_text" class="interval">{{ error_on_save.custom_text }}</Alert>
        <Button @click="save_text('custom_text')" :loading="loading.save_custom_text">保存</Button>
      </div>
    </Modal>

    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">默认dns</div>
        <div class="interval">
          <div class="output output-area mh200 mw512"
            v-html="data.resolv_text ? data.resolv_text.replace(new RegExp(/\n/, 'g'), '<br />') : ''"
            v-on:click="modals.resolv_text = true"></div>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>

    <Modal v-model="modals.resolv_text" title="编辑默认dns">
      <p slot="footer"></p>
      <div class="bottom-interval">
        设置默认dns。一行一个。例如： nameserver 114.114.114.114<br />
        填写最近最快的dns即可
      </div>
      <Input type="textarea" :rows="10" v-model="data.resolv_text" autofocus></Input>
      <div class="right top-interval">
        <Alert type="error" v-if="error_on_save.resolv_text" class="interval">{{ error_on_save.resolv_text }}</Alert>
        <Button @click="save_text('resolv_text')" :loading="loading.save_resolv_text">保存</Button>
      </div>
    </Modal>

    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">网络</div>
        <div class="interval">
          <div class="output output-area mh200 mw512"
            v-html="data.br0_text ? data.br0_text.replace(new RegExp(/\n/, 'g'), '<br />') : ''"
            v-on:click="modals.br0_text = true"></div>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>

    <Modal v-model="modals.br0_text" title="编辑网络">
      <p slot="footer"></p>
      <div class="bottom-interval">
        设置妹子的内网ip，更改address行。<br />
        若要指定物理地址，添加行： hwaddress ether a1:b2:c3:d4:e5:f6
      </div>
      <Input type="textarea" :rows="10" v-model="data.br0_text" autofocus></Input>
      <div class="right top-interval">
        <Alert type="error" v-if="error_on_save.br0_text" class="interval">{{ error_on_save.br0_text }}</Alert>
        <Button @click="save_text('br0_text')" :loading="loading.save_br0_text">保存</Button>
      </div>
    </Modal>

    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">热点配置</div>
        <div class="interval">
          <div class="output output-area mh200 mw512"
            v-html="data.hostapd_text ? data.hostapd_text.replace(new RegExp(/\n/, 'g'), '<br />') : ''"
            v-on:click="modals.hostapd_text = true"></div>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>

    <Modal v-model="modals.hostapd_text" title="编辑热点配置" :styles="{ top: '20px' }">
      <p slot="footer"></p>
      <div class="bottom-interval">
        设置wifi名称，更改ssid行。例如： ssid=girl<br />
        设置信道，更改channel行。取值范围：1-11。例如：channel=11<br />
        设置wifi密码，更改wpa_passphrase行。例如：wpa_passphrase=lastcomm<br />
        设置是否隐藏，更改ignore_broadcast_ssid行。取值：0显示，1隐藏。例如：ignore_broadcast_ssid=1
      </div>
      <Input type="textarea" :rows="20" v-model="data.hostapd_text" autofocus></Input>
      <div class="right top-interval">
        <Alert type="error" v-if="error_on_save.hostapd_text" class="interval">{{ error_on_save.hostapd_text }}</Alert>
        <Button @click="save_text('hostapd_text')" :loading="loading.save_hostapd_text">保存</Button>
      </div>
    </Modal>

    <Row>
      <Col span="1">&nbsp;</Col>
      <Col span="22" id="footer">
        <div class="right">{{ data.measure_temp }}</div>
        <img id="shadow" src="./assets/shadow.jpg" />
        <div v-html="data.girla_active"></div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>

    <Modal v-model="modals.exception" :title="exception.title" width="60" :styles="{ top: '20px', marginBottom: '20px' }">
      <p slot="footer">
        <Button @click="modals.exception = false">关闭</Button>
      </p>

      <div v-html="exception.message.replace(new RegExp(/\n/, 'g'), '<br />')"></div>
    </Modal>

    <Modal v-model="modals.need_restart_dnsmasq" :title="modal_titles.need_restart_dnsmasq">
      <p slot="footer"></p>

      <div> 配置生效需要重启dnsmasq，确认重启dnsmasq吗？ </div>
      <div class="right top-interval">
        <Button @click="systemctl('restart', 'dnsmasq', 'need_restart_dnsmasq')" :loading="loading.restart_dnsmasq">重启dnsmasq</Button>
      </div>
    </Modal>

    <Modal v-model="modals.need_restart_hostapd" title="编辑hostapd.conf成功">
      <p slot="footer"></p>

      <div> 配置生效需要重启hostapd，确认重启hostapd吗？ </div>
      <div class="right top-interval">
        <Button @click="systemctl('restart', 'hostapd', 'need_restart_hostapd')" :loading="loading.restart_hostapd">重启hostapd</Button>
      </div>
    </Modal>

    <Modal v-model="modals.need_restart_networking" title="编辑br0.cfg成功">
      <p slot="footer"></p>

      <div> 配置生效需要重启networking，确认重启networking吗？ </div>
      <div class="right top-interval">
        <Button @click="systemctl('restart', 'networking', 'need_restart_networking')" :loading="loading.restart_networking">重启networking</Button>
      </div>
    </Modal>
  </div>
</template>

<script src="./app.js"></script>
