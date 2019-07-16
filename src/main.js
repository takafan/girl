import Vue from 'vue'
import App from './App.vue'
import './plugins/element.js'
import './assets/app.css'

new Vue({
  render: function (h) { return h(App) },
}).$mount('#app')
