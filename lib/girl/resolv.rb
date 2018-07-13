require 'socket'

module Girl
  class Resolv

    def initialize(host, port, nameservers = [], resolvd_host = nil, resolvd_port = nil, custom_domains = [])
      sock = Socket.new(Socket::AF_INET, Socket::SOCK_DGRAM, 0)
      sock.bind(Socket.sockaddr_in(port, host))
      puts "#{Process.pid} Binding on #{host}:#{port}"

      if nameservers.empty?
        nameservers = %w[ 114.114.114.114 114.114.115.115 ]
      end

      pub_sockaddrs = nameservers.map{|ip| Socket.sockaddr_in( 53, ip ) }

      if resolvd_host && resolvd_port
        rvd_sockaddrs = [ Socket.sockaddr_in( resolvd_port, resolvd_host ) ]
      else
        rvd_sockaddrs = []
      end

      custom_qnames = custom_domains.map{|dom| dom.split('.').map{|sub| [ sub.size ].pack('C') + sub }.join }
      ids = {}
      caches = {}

      loop do
        IO.select([ sock ])

        # https://tools.ietf.org/html/rfc1035#page-26
        data, addrinfo, rflags, *controls = sock.recvmsg
        sender = addrinfo.to_sockaddr

        if data.size <= 12
          puts 'missing header?'
          next
        end

        id = data[0, 2]
        qr = data[2, 2].unpack('B16').first[0]

        qname_len = data[12..-1].index([0].pack('C'))

        if qr == '0'
          qname = data[12, qname_len]
          cache, ttl_ix, expire = caches[qname]

          if cache
            now = Time.new
            if expire > now
              cache[0, 2] = id
              cache[ttl_ix, 4] = [ (expire - now).to_i ].pack('N')
              sock.sendmsg(cache, 0, sender)
              next
            else
              caches.delete(qname)
            end
          end

          is_custom = custom_qnames.any?{|_qname| qname.include?(_qname)}

          if is_custom
            rvd_sockaddrs.each do |sockaddr|
              data[12, qname_len] = swap(qname)
              sock.sendmsg(data, 0, sockaddr)
            end
          else
            pub_sockaddrs.each do |sockaddr|
              sock.sendmsg(data, 0, sockaddr)
            end
          end

          ids[id] = [ sender, is_custom ]
        elsif qr == '1' && ids.include?(id)
          # relay the fastest response, ignore followings
          src, is_custom = ids.delete(id)
          ancount = data[6, 2].unpack('n')
          nscount = data[8, 2].unpack('n')

          if is_custom
            qname = swap(data[12, qname_len])
            data[12, qname_len] = qname
          else
            qname = data[12, qname_len]
          end

          sock.sendmsg(data, 0, src)

          next if ancount == 0 && nscount == 0

          # move to Answer/Authority = Header (12) + QNAME + 0x00 + QTYPE (2) + QCLASS (2)
          ix = 17 + qname_len

          unless data[ix]
            puts "nil answer? ancount #{ancount} nscount #{nscount} #{data.inspect}"
            next
          end

          loop do
            if data[ix].unpack('B8').first[0, 2] == '11' # pointer
              # move to TTL
              ix += 6
              break
            else
              len = data[ix].unpack('C').first
              if len == 0
                # move to TTL
                ix += 5
                break
              end
              # move to next label
              ix += (len + 1)
            end
          end

          # cache data and set expire by TTL of first resource record, ignore followings
          caches[qname] = [ data, ix, Time.new + data[ix, 4].unpack('N').first ]
        end
      end
    end

    def swap(data)
      data
    end

  end
end
