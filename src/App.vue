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
      <div v-if="expire_info">
        {{ expire_info }}
      </div>
      <div class="right">
        <Button @click="systemctl('stop', 'redir', 'redir_service')" :loading="loading.stop_redir">停止</Button>
        <Button @click="systemctl('start', 'redir', 'redir_service')" :loading="loading.start_redir">启动</Button>
        <Button @click="systemctl('restart', 'redir', 'redir_service')" :loading="loading.restart_redir">重启</Button>
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
        <Button @click="systemctl('stop', 'dnsmasq', 'dnsmasq_service')" :loading="loading.stop_dnsmasq">停止</Button>
        <Button @click="systemctl('start', 'dnsmasq', 'dnsmasq_service')" :loading="loading.start_dnsmasq">启动</Button>
        <Button @click="systemctl('restart', 'dnsmasq', 'dnsmasq_service')" :loading="loading.restart_dnsmasq">重启</Button>
      </div>
    </Modal>

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

    <Modal v-model="modals.hostapd_service" title="hostapd服务" :styles="{ top: '20px' }">
      <p slot="footer"></p>
      <div class="row" v-html="data.hostapd_active"></div>
      <div class="output-area mh400 bottom-interval"
           v-html="connections_info" v-if="connections_info">
      </div>
      <div class="right">
        <Button @click="systemctl('stop', 'hostapd', 'hostapd_service')" :loading="loading.stop_hostapd">停止</Button>
        <Button @click="systemctl('start', 'hostapd', 'hostapd_service')" :loading="loading.start_hostapd">启动</Button>
        <Button @click="systemctl('restart', 'hostapd', 'hostapd_service')" :loading="loading.restart_hostapd">重启</Button>
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

    <Modal v-model="modals.networking_service" title="networking服务">
      <p slot="footer"></p>
      <div class="row" v-html="data.networking_active"></div>
      <div class="right">
        <Button @click="systemctl('restart', 'networking', 'networking_service')" :loading="loading.restart_networking">重启</Button>
      </div>
    </Modal>

    <Row class="row">
      <Col span="1">&nbsp;</Col>
      <Col span="22">
        <div class="title bold">远程地址</div>
        <div class="interval">
          <div class="output output-area mh200 mw512" 
            v-html="data.remote_text ? data.remote_text.replace(new RegExp(/\n/, 'g'), '<br />') : ''" 
            v-on:click="modals.remote_text = true">
          </div>
        </div>
      </Col>
      <Col span="1">&nbsp;</Col>
    </Row>

    <Modal v-model="modals.remote_text" title="编辑远程地址">
      <p slot="footer"></p>
      <Input type="textarea" :rows="10" v-model="data.remote_text" autofocus></Input>
      <div class="right top-interval">
        <Alert type="error" v-if="error_on_save.remote_text" class="interval">{{ error_on_save.remote_text }}</Alert>
        <Button @click="save_text('remote_text')" :loading="loading.save_remote_text">保存</Button>
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
        填写域名，该域名走妹子。一行一个。例如：google.com<br />
        填写ip，该ip走妹子。例如：1.255.22.241<br />
        前缀'x'加ip，该ip直连。例如：x1.255.22.241<br />
        通常情况不需要填写ip，妹子会自动识别国外ip绕道。
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

<script>
import axios from 'axios'
import settings from '../settings'

export default {
  name: 'app',
  methods: {
    colour_in: function(text) {
      return text.replace('active (running)', 
        '<span class="running">active (running)</span>').replace('active (exited)', 
        '<span class="running">active (exited)</span>').replace('inactive (dead)', 
        '<span class="dead">inactive (dead)</span>').replace('failed', 
        '<span class="failed">failed</span>')
    },

    load: async function () {
      await axios.post(settings.host + '/api/load').then(res => {

        this.data = res.data
        this.data.dnsmasq_active = this.colour_in(res.data.dnsmasq_active)
        this.data.girla_active = this.colour_in(res.data.girla_active)
        this.data.hostapd_active = this.colour_in(res.data.hostapd_active)
        this.data.networking_active = this.colour_in(res.data.networking_active)
        this.data.redir_active = this.colour_in(res.data.redir_active)
      }).catch(err => {
        this.$Modal.error({ content: err.message })
      })
    },

    save_text: async function(title) {
      let act = 'save_' + title
      this.loading[act] = true
      await axios.post(settings.host + '/api/save_text', { title: title, text: this.data[title] }).then(res => {

        this.loading[act] = false

        if (res.data.success) {
          this.data[title] = res.data.text
          this.modals[title] = false
          this.error_on_save[title] = ''

          if (title == 'br0_text') {
            this.modals.need_restart_networking = true
          } else if (title == 'custom_text' || title == 'remote_text' || title == 'resolv_text') {
            this.modals.need_restart_dnsmasq = true
            this.modal_titles.need_restart_dnsmasq = '保存' + this.translates[title] + '成功'
            if (title == 'remote_text') {
              this.data.redir_active = this.colour_in(res.data.active)
            }
          } else if (title == 'hostapd_text') {
            this.modals.need_restart_hostapd = true
          }
        } else {
          this.error_on_save[title] = res.data.msg
        }
      }).catch(err => {
        this.$Modal.error({ content: err.message })
      })
    },

    set_exception: function(title, message) {
      this.exception.title = title
      this.exception.message = message
      this.modals.exception = true
    },

    show_hostapd_service: async function() {
      this.modals.hostapd_service = true

      await axios.post(settings.host + '/api/dump_wlan0_station') .then(res => {

        if (res.data.success) {
          this.connections_info = res.data.info.replace(/\t/g, '&nbsp;&nbsp;&nbsp;&nbsp;').replace(/\n/g, '<br />')
        }
      }).catch(err => {
        this.$Modal.error({ content: err.message })
      })
    },

    show_redir_service: async function() {
      this.modals.redir_service = true

      let server_port = this.data.remote_text.split(':')

      await axios.get('http://' + server_port[0] + '/girld/expire_info?port=' + server_port[1]) .then(res => {

        if (res.data.success) {
          let expire_time = new Date(res.data.expire_time * 1000)
          this.expire_info = '到期日期：' + expire_time.getFullYear() + '-' + expire_time.getMonth() + '-' + expire_time.getDate()
        }
      }).catch(err => {
        console.log(err)
      })
    },

    systemctl: async function(command, service, modal) {
      let act = command + '_' + service
      this.loading[act] = true

      await axios.post(settings.host + '/api/systemctl', { command: command, service: service }) .then(res => {
        this.loading[act] = false
        this.modals[modal] = false

        this.data[service + '_active'] = this.colour_in(res.data.active)

        if (res.data.success) {
          this.$Message.info(service + '已' + this.translates[command])
        } else {
          this.set_exception(service + this.translates[command] + '失败', res.data.msg)
        }
      }).catch(err => {
        this.$Modal.error({ content: err.message })
      })
    },
    
  },
  mounted: function () {
    this.load()
  },
  data () {
    return {
      connections_info: '',
      data: {},
      error_on_save: {
        custom_text: '',
        hostapd_text: '',
        remote_text: '',
        resolv_text: ''
      },
      exception: {
        message: '',
        title: ''
      },
      expire_info: '',
      loading: {
        restart_dnsmasq: false,
        restart_hostapd: false,
        restart_networking: false,
        restart_redir: false,
        save_custom_text: false,
        save_hostapd_text: false,
        save_remote_text: false,
        save_resolv_text: false,
        start_dnsmasq: false,
        start_hostapd: false,
        start_redir: false,
        stop_dnsmasq: false,
        stop_hostapd: false,
        stop_redir: false
      },
      modals: {
        br0_text: false,
        custom_text: false,
        dnsmasq_service: false,
        exception: false,
        hostapd_text: false,
        hostapd_service: false,
        need_restart_dnsmasq: false,
        need_restart_hostapd: false,
        need_restart_networking: false,
        networking_service: false,
        redir_service: false,
        remote_text: false,
        resolv_text: false
      },
      modal_titles: {
        need_restart_dnsmasq: ''
      },
      translates: {
        custom_text: 'girl.custom.txt',
        remote_text: 'girl.remote',
        resolv_text: 'resolv.conf',
        restart: '重启',
        start: '启动',
        stop: '停止'
      }
    }
  }
}
</script>

