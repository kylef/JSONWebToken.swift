Pod::Spec.new do |spec|
  spec.name = 'JSONWebToken'
  spec.version = '1.5.0'
  spec.summary = 'Swift library for JSON Web Tokens (JWT).'
  spec.homepage = 'https://github.com/kylef/JSONWebToken.swift'
  spec.license = { :type => 'BSD', :file => 'LICENSE' }
  spec.author = { 'Kyle Fuller' => 'kyle@fuller.li' }
  spec.source = { :git => 'https://github.com/kevin-chen-bcgdv/JSONWebToken.swift.git', :branch => "swift-3" }
  spec.source_files = 'Sources/*.swift'
  spec.ios.deployment_target = '8.0'
  spec.osx.deployment_target = '10.9'
  spec.tvos.deployment_target = '9.0'
  spec.requires_arc = true
  spec.dependency 'CryptoSwift'
  spec.module_name = 'JWT'
end
