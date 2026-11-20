# frozen_string_literal: true

require_relative 'lib/bydev/version'

Gem::Specification.new do |spec|
  spec.name = 'bydev-server'
  spec.version = Bydev::VERSION
  spec.summary = '데브 라이선스 API 판매자 서버 도우미 — 웹훅 서명 검증 · access_token · licenseToken 검증'
  spec.description = '판매자 서버(Rails · Sinatra 등)에서 쓰는 두 함수를 제공합니다: Standard Webhooks v1 서명 검증과 Ed25519 토큰 검증. 표준 라이브러리만 사용합니다.'
  spec.authors = ['한비트 주식회사']
  spec.homepage = 'https://developedby.dev/sell/docs/sdks'
  spec.licenses = ['MIT', 'Apache-2.0']
  spec.required_ruby_version = '>= 3.3'
  spec.files = Dir['lib/**/*.rb'] + ['README.md', 'LICENSE-MIT', 'LICENSE-APACHE']
  spec.require_paths = ['lib']
  spec.metadata['source_code_uri'] = 'https://github.com/developedby-dev/server-ruby'
  spec.metadata['documentation_uri'] = 'https://developedby.dev/sell/docs/sdks'
  spec.metadata['rubygems_mfa_required'] = 'true'
end
