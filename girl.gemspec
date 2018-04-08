# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'girl/version'

Gem::Specification.new do |spec|
  spec.name          = 'girl'
  spec.version       = Girl::VERSION
  spec.authors       = ['unknown']
  spec.email         = ['unknown']

  spec.summary       = %q{最终路由器彼女}
  spec.description   = %q{the last 江南style traffic relay}
  spec.homepage      = 'http://lastcomm.com/'
  spec.license       = 'MIT'

  spec.files         = %w[
girl.gemspec
lib/girl.rb
lib/girl/hex.rb
lib/girl/redir.rb
lib/girl/relay.rb
lib/girl/version.rb
lib/girl/xeh.rb
  ]

  spec.require_paths = ['lib']
end
