Pod::Spec.new do |spec|
  spec.name = 'JSONWebToken'
  spec.version = '2.1.0'
  spec.summary = 'Swift library for JSON Web Tokens (JWT).'
  spec.homepage = 'https://github.com/kylef/JSONWebToken.swift'
  spec.license = { :type => 'BSD', :file => 'LICENSE' }
  spec.author = { 'Kyle Fuller' => 'kyle@fuller.li' }
  spec.source = { :git => 'https://github.com/kylef/JSONWebToken.swift.git', :tag => "#{spec.version}" }
  spec.source_files = 'Sources/*.swift'
  spec.ios.deployment_target = '8.0'
  spec.osx.deployment_target = '10.9'
  spec.tvos.deployment_target = '9.0'
  spec.watchos.deployment_target = '2.0'
  spec.requires_arc = true
  spec.dependency 'CryptoSwift', '~> 0.6.1'
  spec.module_name = 'JWT'
end
