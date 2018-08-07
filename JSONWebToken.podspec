Pod::Spec.new do |spec|
  spec.name = 'JSONWebToken'
  spec.version = '3.0.0'
  spec.summary = 'Swift library for JSON Web Tokens (JWT).'
  spec.homepage = 'https://github.com/kylef/JSONWebToken.swift'
  spec.license = { :type => 'BSD', :file => 'LICENSE' }
  spec.author = { 'Kyle Fuller' => 'kyle@fuller.li' }
  spec.source = { :git => 'https://github.com/kylef/JSONWebToken.swift.git' }
  spec.source_files = 'Sources/JWT/*.swift', 'Build-Phases/common-crypto.sh'
  spec.ios.deployment_target = '8.0'
  spec.osx.deployment_target = '10.9'
  spec.tvos.deployment_target = '9.0'
  spec.watchos.deployment_target = '2.0'
  spec.requires_arc = true
  spec.module_name = 'JWT'
  spec.exclude_files = ['Sources/JWT/HMACCryptoSwift.swift']

  spec.swift_version = '4.0'

  if ARGV.include?('lint')
    spec.pod_target_xcconfig = {
      'SWIFT_INCLUDE_PATHS' => Dir.pwd,
    }
  else
    spec.pod_target_xcconfig = {
      'SWIFT_INCLUDE_PATHS' => '$(PODS_ROOT)/JSONWebToken/',
    }
  end

  spec.preserve_paths = 'Build-Phases/*.sh'
  spec.script_phase = { :name => 'CommonCrypto', :script => 'sh $SRCROOT/JSONWebToken/Build-Phases/common-crypto.sh', :execution_position => :before_compile }
end
