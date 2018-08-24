// nginx conf add line: proxy_set_header Host $host;
// HOST=192.168.1.59 yarn serve
let api_host = process.env.API_HOST || ''

console.log('api host: ' + api_host)

export default {
  api_host: api_host
}
