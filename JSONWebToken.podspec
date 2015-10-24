Pod::Spec.new do |spec|
  spec.name = 'JSONWebToken'
  spec.version = '1.4.1'
  spec.summary = 'Swift library for JSON Web Tokens (JWT).'
  spec.homepage = 'https://github.com/kylef/JSONWebToken.swift'
  spec.license = { :type => 'BSD', :file => 'LICENSE' }
  spec.author = { 'Kyle Fuller' => 'kyle@fuller.li' }
  spec.social_media_url = 'http://twitter.com/kylefuller'
  spec.source = { :git => 'https://github.com/kylef/JSONWebToken.swift.git', :tag => "#{spec.version}" }
  spec.source_files = 'JWT/*.swift'
  spec.ios.deployment_target = '8.0'
  spec.osx.deployment_target = '10.9'
  spec.requires_arc = true
  spec.dependency 'CryptoSwift', '0.1.1'
  spec.module_name = 'JWT'
end
