# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'girl/version'

Gem::Specification.new do |spec|
  spec.name          = 'girl'
  spec.version       = Girl::VERSION
  spec.authors       = ['takafan']
  spec.email         = ['qqtakafan@gmail.com']

  spec.summary       = %q{妹子}
  spec.description   = %q{escape evil.}
  spec.homepage      = 'https://github.com/takafan/girl'
  spec.license       = 'MIT'

  spec.files         = %w[
girl.gemspec
lib/girl.rb
lib/girl/concurrent_hash.rb
lib/girl/custom_dns_query.rb
lib/girl/head.rb
lib/girl/proxy_custom.rb
lib/girl/proxy_worker.rb
lib/girl/proxy.rb
lib/girl/proxyd_custom.rb
lib/girl/proxyd_worker.rb
lib/girl/proxyd.rb
lib/girl/relay_worker.rb
lib/girl/relay.rb
lib/girl/resolv_custom.rb
lib/girl/resolvd_worker.rb
lib/girl/resolvd.rb
lib/girl/ssl_worker.rb
lib/girl/ssl.rb
lib/girl/version.rb
  ]

  spec.require_paths = ['lib']
end
