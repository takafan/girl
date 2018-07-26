# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'girl/version'

Gem::Specification.new do |spec|
  spec.name          = 'girl'
  spec.version       = Girl::VERSION
  spec.authors       = ['takafan']
  spec.email         = ['takafan@163.com']

  spec.summary       = %q{妹子}
  spec.description   = %q{a 江南style traffic relay}
  spec.homepage      = 'http://lastcomm.com/'
  spec.license       = 'MIT'

  spec.files         = %w[
girl.gemspec
lib/girl.rb
lib/girl/hex.rb
lib/girl/mirror.rb
lib/girl/mirrord.rb
lib/girl/redir.rb
lib/girl/relay.rb
lib/girl/resolv.rb
lib/girl/resolvd.rb
lib/girl/version.rb
lib/girl/xeh.rb
  ]

  spec.require_paths = ['lib']
end
