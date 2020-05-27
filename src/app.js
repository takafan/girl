import axios from 'axios'

export default {
  name: 'app',
  methods: {
    check_hostapd: function( checked ) {
      let command = checked ? 'enable' : 'disable'
      this.systemctl( command, 'hostapd' )
    },

    check_proxy: function( checked ) {
      let command = checked ? 'enable' : 'disable'
      this.systemctl( command, 'proxy' )
    },

    ip: function() {
      window.open( this.http_host + '/api/ip', '_blank' )
    },

    load: function () {
      axios.post( this.http_host + '/api/load' ).then( res => {
        let data = res.data
        let enableds = {}
        let runnings = {}
        let colour_actives = {}
        let poppings = {}
        let loadings = {}

        Object.entries( data.loadeds ).forEach( pair => {
          enableds[ pair[ 0 ] ] = pair[ 1 ].includes( 'enabled;' )
        })

        Object.entries( data.actives ).forEach( pair => {
          runnings[ pair[ 0 ] ] = pair[ 1 ].includes( 'running' )
          colour_actives[ pair[ 0 ] ] = pair[ 1 ].replace('active (running)',
            '<span class="running">active (running)</span>' ).replace( 'active (exited)',
            '<span class="running">active (exited)</span>' ).replace( 'inactive (dead)',
            '<span class="dead">inactive (dead)</span>' ).replace( 'failed',
            '<span class="failed">failed</span>' )
          loadings[ 'restart@' + pair[ 0 ] ] = false
          loadings[ 'start@' + pair[ 0 ] ] = false
          loadings[ 'stop@' + pair[ 0 ] ] = false
          loadings[ 'enable@' + pair[ 0 ] ] = false
          loadings[ 'disable@' + pair[ 0 ] ] = false
        })

        Object.entries( data.texts ).forEach( pair => {
          loadings[ 'save@' + pair[ 0 ] ] = false
        })

        this.runnings = runnings
        this.colour_actives = colour_actives
        this.enableds = enableds
        this.poppings = poppings
        this.loadings = loadings
        this.texts = data.texts
        this.conf = JSON.parse( data.texts[ 'girl.conf.json' ] )
        this.is_locked = data.is_locked
        this.measure_temp = data.measure_temp
      }).catch( err => {
        console.log( err )
      })
    },

    save_text: function( file ) {
      this.loadings[ 'save@' + file ] = true
      axios.post( this.http_host + '/api/save_text', { file: file, text: this.texts[ file ] } ).then( res => {
        this.saved_file( file )
      }).catch( err => {
        console.log( err )
        if ( file == 'girl.remote.txt' ) {
          this.saved_file( file )
        }
      })
    },

    saved_file: function( file ) {
      this.loadings[ 'save@' + file ] = false
      this.editing = null
      this.load()
      this.$notify.success({
        title: '成功',
        message: this.translates[ file ] + ' 已更新',
        type: 'success'
      })
    },

    show_service: function( service ) {
      if ( this.editing == service ) {
        this.editing = null
        return
      }
      this.editing = service
      if ( service == 'proxy' ) {
        this.set_expire_info()
      }
    },

    set_expire_info: function() {
      let conf = this.conf
      if ( conf ) {
        axios.get( 'http://' + conf.proxyd_host + ':3000/expire_info/' + conf.im ).then( res => {
          let data = res.data
          this.expire_info.input = data.input
          this.expire_info.output = data.output
          this.expire_info.expire = data.expire
        }).catch( err => {
          console.log( err )
        })
      }
    },

    systemctl: function( command, service ) {
      this.loadings[ command + '@' + service ] = true
      axios.post( this.http_host + '/api/systemctl', { command: command, service: service } ).then( res => {
        this.executed_command( command, service )
      }).catch( err => {
        console.log( err )
        if ( service == 'proxy' ) {
          this.executed_command( command, service )
        }
      })
    },

    executed_command: function( command, service ) {
      this.loadings[ command + '@' + service ] = false
      if ( [ 'start', 'stop', 'restart' ].includes( command ) ) {
        this.editing = null
      }
      this.load()
      if ( service == 'proxy' ) {
        this.set_expire_info()
      }
      this.$notify.success({
        title: '成功',
        message: this.translates[ service ] + ' 已' + this.translates[ command ],
        type: 'success'
      })
    },

    station: function() {
      window.open( this.http_host + '/api/station', '_blank' )
    },

    tail: function( service ) {
      window.open( this.http_host + '/api/tail/' + service, '_blank' )
    }
  },
  mounted: function () {
    this.load()
  },
  data () {
    return {
      colour_actives: {},
      editing: null,
      enableds: {},
      expire_info: {
        input: '-',
        output: '-',
        expire: '-'
      },
      http_host: process.env.VUE_APP_HOST ? ( 'http://' + process.env.VUE_APP_HOST ) : '',
      is_locked: false,
      loadings: {},
      measure_temp: null,
      poppings: {},
      runnings: {},
      texts: {},
      conf: {},
      translates: {
        dhcpcd: '网卡',
        disable: '关闭自动启动',
        dnsmasq: 'dhcp租约',
        enable: '打开自动启动',
        hostapd: '热点',
        restart: '重启',
        start: '启动',
        status: '刷新',
        stop: '停止',
        proxy: '代理近端',
        'dnsmasq.d/wlan0.conf': 'dhcp租约配置',
        'dhcpcd.conf': '网卡配置',
        'girl.remote.txt': '交给远端解析的域名列表',
        'hostapd.conf': '热点配置'
      }
    }
  }
}
