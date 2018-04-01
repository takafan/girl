let host = 'http://192.168.1.59'

if (process.env.NODE_ENV === 'production') {
  host = '' // nginx conf add line: proxy_set_header Host $host;
}

console.log('host: ' + host)

module.exports = {
  host: host
}
