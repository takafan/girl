import Vue from 'vue'
import App from './App.vue'
import iview from 'iview'
import 'iview/dist/styles/iview.css'
import './assets/app.css'

Vue.use(iview)

new Vue({
  el: '#app',
  render: h => h(App)
})
