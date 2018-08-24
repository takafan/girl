// nginx conf add line: proxy_set_header Host $host;
// HOST=192.168.1.59 yarn serve
let host = process.env.HOST || ''

console.log('host: ' + host)

export default {
  host: host
}
