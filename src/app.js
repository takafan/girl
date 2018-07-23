import axios from 'axios'
import settings from '../settings'

export default {
  name: 'app',
  methods: {
    check_hostapd: function(checked) {
      this.systemctl(checked ? 'enable' : 'disable', 'hostapd', 'hostapd_service')
    },

    colour_in: function(text) {
      return text.replace('active (running)',
        '<span class="running">active (running)</span>').replace('active (exited)',
        '<span class="running">active (exited)</span>').replace('inactive (dead)',
        '<span class="dead">inactive (dead)</span>').replace('failed',
        '<span class="failed">failed</span>')
    },

    load: function () {
      axios.post(settings.host + '/api/load').then(res => {
        this.data = res.data
        this.data.dnsmasq_active = this.colour_in(res.data.dnsmasq_active)
        this.data.girla_active = this.colour_in(res.data.girla_active)
        this.data.hostapd_active = this.colour_in(res.data.hostapd_active)
        this.data.networking_active = this.colour_in(res.data.networking_active)
        this.data.redir_active = this.colour_in(res.data.redir_active)
        this.data.dnsmasq_running = res.data.dnsmasq_active.includes('running')
        this.data.hostapd_running = res.data.hostapd_active.includes('running')
        this.data.networking_running = res.data.networking_active.includes('running')
        this.data.redir_running = res.data.redir_active.includes('running')
        this.data.hostapd_enabled = res.data.hostapd_loaded.includes('enabled;')
      }).catch(err => {
        this.$Modal.error({ content: err.message })
      })
    },

    save_text: function(title) {
      let act = 'save_' + title
      this.loading[act] = true
      axios.post(settings.host + '/api/save_text', { title: title, text: this.data[title] }).then(res => {
        this.loading[act] = false

        if (res.data.success) {
          this.data[title] = res.data.text
          this.modals[title] = false
          this.error_on_save[title] = ''

          if (title == 'br0_text') {
            this.modals.need_restart_networking = true
          } else if (title == 'relay_text') {
            this.modals.need_restart_redir = true
          } else if (title == 'custom_text' || title == 'resolv_text' || title == 'dns_text') {
            this.modals.need_restart_dnsmasq = true
            this.modal_titles.need_restart_dnsmasq = '保存' + this.translates[title] + '成功'
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

    show_hostapd_service: function() {
      this.modals.hostapd_service = true

      axios.post(settings.host + '/api/dump_wlan0_station').then(res => {

        if (res.data.success) {
          this.connections_info = res.data.info.replace(/\t/g, '&nbsp;&nbsp;&nbsp;&nbsp;').replace(/\n/g, '<br />')
        }
      }).catch(err => {
        this.$Modal.error({ content: err.message })
      })
    },

    show_redir_service: function() {
      if (!this.data.relay_text) {
        return
      }

      this.modals.redir_service = true

      let host = this.data.relay_text.split("\n")[0].split(':')[0]

      axios.get('http://' + host + ':3000/girld/expire_info?im=' + this.data.im).then(res => {
        if (res.data.success) {
          let expire_info = '本月已用流量 in: ' + res.data.input + ' out: ' + res.data.output
          if (res.data.expire_time) {
            let expire_time = new Date(res.data.expire_time * 1000)
            expire_info += '<br />' + '到期日期：' + expire_time.getFullYear() + '-' + ( expire_time.getMonth() + 1 ) + '-' + expire_time.getDate()
          }
          this.expire_info = expire_info

          if (res.data.migrate_info) {
            axios.post(settings.host + '/api/update_girl_addr', { relay_text: res.data.migrate_info[0], resolv_text: res.data.migrate_info[1] }).then(res2 => {
              if (res2.data.success) {
                this.data.relay_text = res2.data.relay_text
                this.data.resolv_text = res2.data.resolv_text
                this.data.dnsmasq_active = this.colour_in(res2.data.dnsmasq_active)
                this.data.redir_active = this.colour_in(res2.data.redir_active)
                this.data.dnsmasq_running = res2.data.dnsmasq_active.includes('running')
                this.data.redir_running = res2.data.redir_active.includes('running')

                axios.post('http://' + host + ':3000/girld/complete_migrate?im=' + this.data.im).then(res3 => {
                  if (res3.data.success) {
                    console.log('migrate completed')
                  }
                })
              }
            })
          }
        }
      }).catch(err => {
        console.log(err)
      })
    },

    systemctl: function(command, service, modal) {
      let act = command + '_' + service
      this.loading[act] = true

      axios.post(settings.host + '/api/systemctl', { command: command, service: service }).then(res => {
        if (this.loading[act]) {
          this.loading[act] = false
        }

        if (res.data.active) {
          this.data[service + '_active'] = this.colour_in(res.data.active)
        }

        if ([ 'disable', 'enable' ].includes(command)) {
          this.data[service + '_enabled'] = res.data.loaded.includes('enabled;')
        }

        if ([ 'start', 'stop', 'restart' ].includes(command)) {
          this.data[ service + '_running' ] = res.data.active.includes('running')
          this.modals[modal] = false
        }

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
        br0_text: '',
        custom_text: '',
        dns_text: '',
        hostapd_text: '',
        relay_text: '',
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
        save_relay_text: false,
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
        dns_text: false,
        dnsmasq_service: false,
        exception: false,
        hostapd_text: false,
        hostapd_service: false,
        need_restart_dnsmasq: false,
        need_restart_hostapd: false,
        need_restart_networking: false,
        networking_service: false,
        redir_service: false,
        relay_text: false,
        resolv_text: false
      },
      modal_titles: {
        need_restart_dnsmasq: ''
      },
      translates: {
        custom_text: 'girl.custom.txt',
        disable: '关闭开机自动启动',
        dns_text: 'resolv.conf',
        enable: '打开开机自动启动',
        relay_text: 'girl.relay',
        resolv_text: 'girl.resolv',
        restart: '重启',
        start: '启动',
        stop: '停止'
      }
    }
  }
}