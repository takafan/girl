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
  spec.description   = %q{while network is evil, here's a patch.}
  spec.homepage      = 'https://github.com/takafan/girl'
  spec.license       = 'MIT'

  spec.files         = %w[
girl.gemspec
lib/girl.rb
lib/girl/hex.rb
lib/girl/p2p1.rb
lib/girl/p2p2.rb
lib/girl/p2pd.rb
lib/girl/resolv.rb
lib/girl/resolvd.rb
lib/girl/tun.rb
lib/girl/tund.rb
lib/girl/usr.rb
lib/girl/version.rb
  ]

  spec.require_paths = ['lib']
  spec.add_runtime_dependency "nio4r", "~> 2.3"
end
