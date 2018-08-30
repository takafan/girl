import axios from 'axios'

export default {
  name: 'app',
  methods: {
    check_hostapd: function( checked ) {
      let command = checked ? 'enable' : 'disable'
      this.systemctl( command, 'hostapd' )
    },

    check_mirror_sshd: function( checked ) {
      let command = checked ? 'enable' : 'disable'
      this.systemctl( command, 'mirror_sshd' )
    },

    colour_in: function(text) {
      return text.replace('active (running)',
        '<span class="running">active (running)</span>').replace('active (exited)',
        '<span class="running">active (exited)</span>').replace('inactive (dead)',
        '<span class="dead">inactive (dead)</span>').replace('failed',
        '<span class="failed">failed</span>')
    },

    load: function () {
      axios.post( this.http_host + '/api/load' ).then( res => {
        let data = res.data
        let enableds = {}
        let colour_actives = {}
        let runnings = {}
        let poppings = { exception: false }
        let loadings = {}
        let error_on_saves = {}

        Object.entries( data.loadeds ).forEach( pair => {
          enableds[ pair[0] ] = pair[1].includes('enabled')
        })

        Object.entries( data.actives ).forEach( pair => {
          colour_actives[ pair[0] ] = this.colour_in(pair[1])
          runnings[ pair[0] ] = pair[1].includes('running')
          poppings[ 'service@' + pair[0] ] = false
          loadings[ 'restart@' + pair[0] ] = false
          loadings[ 'start@' + pair[0] ] = false
          loadings[ 'stop@' + pair[0] ] = false
          loadings[ 'enable@' + pair[0] ] = false
          loadings[ 'disable@' + pair[0] ] = false
        })

        Object.entries( data.texts ).forEach( pair => {
          poppings[ 'text@' + pair[0] ] = false
          poppings[ 'saved@' + pair[0] ] = false
          loadings[ 'save@' + pair[0] ] = false
          error_on_saves[ pair[0] ] = ''
        })

        this.colour_actives = colour_actives
        this.runnings = runnings
        this.enableds = enableds
        this.poppings = poppings
        this.loadings = loadings
        this.texts = data.texts
        this.is_locked = data.is_locked
        this.measure_temp = data.measure_temp
        this.error_on_saves = error_on_saves
      }).catch( err => {
        this.$Modal.error({ content: err.message })
      })
    },

    save_text: function( file ) {
      this.loadings[ 'save@' + file ] = true
      axios.post( this.http_host + '/api/save_text', { file: file, text: this.texts[ file ] } ).then( res => {
        this.loadings[ 'save@' + file ] = false
        let data = res.data
        if ( data.success ) {
          this.poppings[ 'text@' + file ] = false
          this.error_on_saves[ file ] = ''
          if ( this.poppings.hasOwnProperty( 'saved@' + file ) ) {
            this.poppings[ 'saved@' + file ] = true
          } else {
            this.$Message.info( '已保存' )
          }
        } else {
          this.error_on_saves[ file ] = data.msg
        }
      }).catch( err => {
        this.$Modal.error({ content: err.message })
      })
    },

    set_exception: function( title, message ) {
      this.exception.title = title
      this.exception.message = message
      this.poppings.exception = true
    },

    show_hostapd_service: function() {
      this.poppings[ 'service@hostapd' ] = true
      axios.post( this.http_host + '/api/dump_wlan0_station' ).then( res => {
        let data = res.data
        if ( data.success ) {
          this.connections_info = data.info.replace(/\t/g, '&nbsp;&nbsp;&nbsp;&nbsp;').replace(/\n/g, '<br />')
        }
      }).catch( err => {
        this.$Modal.error({ content: err.message })
      })
    },

    show_redir_service: function() {
      this.poppings[ 'service@redir' ] = true
      let text = this.texts[ 'girl.relayd' ]
      if ( !text ) {
        return
      }
      let host = text.split("\n")[0].split(':')[0]
      let im = this.texts[ 'girl.im' ].split("\n")[0].split(':')[0]
      axios.get( 'http://' + host + ':3000/girld/expire_info?im=' + im ).then( res => {
        let data = res.data
        if ( data.success ) {
          let expire_info = '本月已用流量 in: ' + data.input + ' out: ' + data.output
          if ( data.expire_time ) {
            let expire_time = new Date( data.expire_time * 1000 )
            expire_info += '<br />' + '到期日期：' + expire_time.getFullYear() + '-' + ( expire_time.getMonth() + 1 ) + '-' + expire_time.getDate()
          }
          this.expire_info = expire_info
        }
      }).catch( err => {
        console.log(err)
      })
    },

    systemctl: function( command, service, from_popping ) {
      this.loadings[ command + '@' + service ] = true
      axios.post( this.http_host + '/api/systemctl', { command: command, service: service } ).then( res => {
        this.loadings[ command + '@' + service ] = false
        let data = res.data
        if ( data.success ) {
          this.colour_actives[ service ] = this.colour_in( data.active )
          if ([ 'start', 'stop', 'restart' ].includes( command )) {
            this.runnings[ service ] = data.active.includes( 'running' )
            if ( from_popping ) {
              this.poppings[ from_popping ] = false
            } else {
              this.poppings[ 'service@' + service ] = false
            }
          } else if ([ 'disable', 'enable' ].includes( command )) {
            this.enableds[ service ] = data.loaded.includes( 'enabled;' )
          }
          this.$Message.info( '已' + this.translates[ command ] )
        } else {
          this.set_exception( this.translates[ command ] + '失败', data.msg )
        }
      }).catch( err => {
        this.$Modal.error({ content: err.message })
      })
    }
  },
  mounted: function () {
    this.load()
  },
  data () {
    return {
      http_host: process.env.VUE_APP_HOST ? ( 'http://' + process.env.VUE_APP_HOST ) : '',
      connections_info: '',
      colour_actives: {},
      enableds: {},
      error_on_saves: {},
      exception: {
        message: '',
        title: ''
      },
      expire_info: '',
      is_locked: false,
      loadings: {},
      measure_temp: null,
      poppings: {},
      runnings: {},
      texts: {},
      translates: {
        disable: '关闭自动启动',
        enable: '打开自动启动',
        restart: '重启',
        start: '启动',
        stop: '停止'
      }
    }
  }
}
