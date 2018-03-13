let host = 'http://10.17.2.59'

if (process.env.NODE_ENV === 'production') {
  host = '' // nginx conf add line: proxy_set_header Host $host;
}

console.log('host: ' + host)

module.exports = {
  host: host
}
