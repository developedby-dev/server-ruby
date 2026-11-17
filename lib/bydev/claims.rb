# frozen_string_literal: true

module Bydev
  # 검증된 access_token 클레임 (명세 12절). `sub`가 그 판매자용 가명 식별자다.
  AccessClaims = Data.define(:iss, :sub, :aud, :client_id, :scope, :iat, :exp, :jti) do
    def self.read(c)
      new(iss: Claims.text(c, 'iss'), sub: Claims.text(c, 'sub'), aud: Claims.text(c, 'aud'),
          client_id: Claims.text(c, 'client_id'), scope: Claims.text(c, 'scope'), iat: Claims.integer(c, 'iat'),
          exp: Claims.integer(c, 'exp'), jti: Claims.text(c, 'jti'))
    end
  end

  # 검증된 licenseToken 클레임 (명세 9 · 12절). `build_id`는 세션을 얻을 때 앱이 보낸 대상 · 버전으로 데브가 확정한 빌드(ADR-0049) —
  # 확정하지 못했으면 nil.
  LicenseClaims = Data.define(:iss, :sub, :aud, :product_id, :device_id, :sid, :generation, :iat, :exp, :build_id) do
    def self.read(c)
      new(iss: Claims.text(c, 'iss'), sub: Claims.text(c, 'sub'), aud: Claims.text(c, 'aud'),
          product_id: Claims.text(c, 'product_id'), device_id: Claims.text(c, 'device_id'), sid: Claims.text(c, 'sid'),
          generation: Claims.integer(c, 'generation'), iat: Claims.integer(c, 'iat'), exp: Claims.integer(c, 'exp'),
          build_id: Claims.optional_text(c, 'build_id'))
    end
  end

  # @api private 클레임 읽기 — 모양이 다르면 TOKEN_INVALID.
  module Claims
    def self.text(c, key)
      value = c[key]
      raise Error.new(Codes::TOKEN_INVALID, "클레임 #{key}가 문자열이 아니다") unless value.is_a?(String)

      value
    end

    # 없으면 nil, 있는데 문자열이 아니면 TOKEN_INVALID.
    def self.optional_text(c, key)
      c[key].nil? ? nil : text(c, key)
    end

    def self.integer(c, key)
      value = c[key]
      raise Error.new(Codes::TOKEN_INVALID, "클레임 #{key}가 정수가 아니다") unless value.is_a?(Integer)

      value
    end
  end
end
