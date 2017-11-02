Pod::Spec.new do |spec|
  spec.name = 'JSONWebToken'
  spec.version = '2.2.0'
  spec.summary = 'Swift library for JSON Web Tokens (JWT).'
  spec.homepage = 'https://github.com/kylef/JSONWebToken.swift'
  spec.license = { :type => 'BSD', :file => 'LICENSE' }
  spec.author = { 'Kyle Fuller' => 'kyle@fuller.li' }
  spec.source = { :git => 'https://github.com/kylef/JSONWebToken.swift.git', :tag => "#{spec.version}" }
  spec.source_files = 'Sources/JWT/*.swift'
  spec.ios.deployment_target = '8.0'
  spec.osx.deployment_target = '10.9'
  spec.tvos.deployment_target = '9.0'
  spec.watchos.deployment_target = '2.0'
  spec.requires_arc = true
  spec.module_name = 'JWT'
  spec.exclude_files = ['Sources/JWT/HMACCryptoSwift.swift']

  if ARGV.include?('lint')
    spec.pod_target_xcconfig = {
      'SWIFT_INCLUDE_PATHS' => Dir.pwd,
    }
  else
    spec.pod_target_xcconfig = {
      'SWIFT_INCLUDE_PATHS' => '$(PODS_ROOT)/JSONWebToken/',
    }
  end

  spec.preserve_paths = 'CommonCrypto/{shim.h,module.modulemap}'
end
