import axios from 'axios'

export default {
  name: 'app',
  methods: {
    check_hostapd: function( checked ) {
      let command = checked ? 'enable' : 'disable'
      this.systemctl( command, 'hostapd' )
    },

    check_tun: function( checked ) {
      let command = checked ? 'enable' : 'disable'
      this.systemctl( command, 'tun' )
    },

    check_resolv: function( checked ) {
      let command = checked ? 'enable' : 'disable'
      this.systemctl( command, 'resolv' )
    },

    colour_in: function( text ) {
      return text.replace('active (running)',
        '<span class="running">active (running)</span>' ).replace( 'active (exited)',
        '<span class="running">active (exited)</span>' ).replace( 'inactive (dead)',
        '<span class="dead">inactive (dead)</span>' ).replace( 'failed',
        '<span class="failed">failed</span>' )
    },

    ip: function() {
      window.open( this.http_host + '/api/ip', '_blank' )
    },

    load: function () {
      axios.post( this.http_host + '/api/load' ).then( res => {
        let data = res.data
        let enableds = {}
        let colour_actives = {}
        let runnings = {}
        let poppings = {}
        let loadings = {}

        Object.entries( data.loadeds ).forEach( pair => {
          enableds[ pair[ 0 ] ] = pair[ 1 ].includes( 'enabled;' )
        })

        Object.entries( data.actives ).forEach( pair => {
          colour_actives[ pair[ 0 ] ] = this.colour_in( pair[ 1 ] )
          runnings[ pair[ 0 ] ] = pair[ 1 ].includes( 'running' )
          loadings[ 'restart@' + pair[ 0 ] ] = false
          loadings[ 'start@' + pair[ 0 ] ] = false
          loadings[ 'stop@' + pair[ 0 ] ] = false
          loadings[ 'enable@' + pair[ 0 ] ] = false
          loadings[ 'disable@' + pair[ 0 ] ] = false
        })

        Object.entries( data.texts ).forEach( pair => {
          loadings[ 'save@' + pair[ 0 ] ] = false
        })

        this.loadeds = data.loadeds
        this.colour_actives = colour_actives
        this.runnings = runnings
        this.enableds = enableds
        this.poppings = poppings
        this.loadings = loadings
        this.texts = data.texts
        this.is_locked = data.is_locked
        this.measure_temp = data.measure_temp
      }).catch( err => {
        console.log( err.message )
      })
    },

    save_text: function( file ) {
      this.loadings[ 'save@' + file ] = true
      axios.post( this.http_host + '/api/save_text', { file: file, text: this.texts[ file ] } ).then( res => {
        this.loadings[ 'save@' + file ] = false
        let data = res.data
        this.editing = null
        this.load()
        this.$notify.success({
          title: '成功',
          message: this.translates[ file ] + ' 已更新',
          type: 'success'
        })
      }).catch( err => {
        console.log( err.message )
      })
    },

    show_service: function( service ) {
      if ( this.editing == service ) {
        this.editing = null
        return
      }

      this.editing = service

      if ( service == 'tun' ) {
        let text = this.texts[ 'girl.tund' ]
        if ( !text ) {
          return
        }
        let host = text.split( "\n" )[ 0 ].split( ':' )[ 0 ]
        let im = this.texts[ 'girl.im' ].split( "\n" )[ 0 ].split( ':' )[ 0 ]
        axios.get( 'http://' + host + ':3000/girld/expire_info?im=' + im ).then( res => {
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
        axios.post( this.http_host + '/api/systemctl', { command: 'status', service: service } ).then( res2 => {
          this.loadings[ command + '@' + service ] = false
          let data = res2.data
          this.colour_actives[ service ] = this.colour_in( data.active )
          this.runnings[ service ] = data.active.includes( 'running' )
          this.enableds[ service ] = data.loaded.includes( 'enabled;' )
          if ( [ 'start', 'stop', 'restart' ].includes( command ) ) {
            this.editing = null
          }
          this.$notify.success({
            title: '成功',
            message: this.translates[ service ] + ' 已' + this.translates[ command ],
            type: 'success'
          })
        })
      }).catch( err => {
        console.log( err.message )
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
      loadeds: {},
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
        tun: '网关近端',
        resolv: 'dns近端',
        'dnsmasq.d/wlan0.conf': 'dhcp租约配置',
        'dhcpcd.conf': '网卡配置',
        'girl.custom.txt': '自定义',
        'girl.tund': '远端地址',
        'hostapd.conf': '热点配置',
        'nameservers.txt': 'dns默认地址'
      }
    }
  }
}
