# frozen_string_literal: true

require 'digest'
require 'json'
require 'openssl'

module Bydev
  # 판매자 서버의 토큰 검증 (명세 9 · 12절 · 안내서 09장) — 발견 문서와 JWKS를 받아 access_token(`at+jwt`) · licenseToken(`license+jwt`)의
  # 서명 · `iss` · `aud` · `exp`를 확인한다. 스레드 사이에 나눠 쓴다 — 인스턴스 하나를 오래 둔다(프로세스마다 하나).
  #
  # 여러 프로세스(Puma 작업자 등)가 받은 JWKS를 나누려면 Rails 캐시 모양(`read(key)` · `write(key, value, expires_in:)`)의 `cache:`를 준다.
  # JWKS는 응답의 `Cache-Control: max-age`까지만 두고(명세 9.1), 모르는 `kid`는 마지막으로 받은 지 1분이 지났을 때만 다시 받는다.
  class ServerVerifier
    # SubjectPublicKeyInfo(Ed25519)의 앞부분 — 뒤에 32바이트 공개키가 붙는다 (RFC 8410)
    SPKI_PREFIX = ['302a300506032b6570032100'].pack('H*').freeze
    CACHE_PREFIX = 'bydev.server.'

    # @param http [#call, nil] GET — url → [상태, 소문자 헤더, 본문] (기본 `Http.get`)
    # @param clock [#call, nil] 지금(Unix 초) — 시험에서 준다
    # @param cache [#read & #write, nil] Rails 캐시 모양(선택)
    def initialize(base_url:, client_id:, http: nil, clock: nil, cache: nil)
      @base_url = base_url.chomp('/')
      @client_id = client_id
      @http = http || Http.method(:get)
      @clock = clock || -> { Time.now.to_f }
      @cache = cache
      @mutex = Mutex.new
      @discovery = nil
      @key_set = nil
    end

    # access_token(at+jwt)을 검증한다 — 앱이 판매자 서버에 보낸 토큰으로 사용자를 알아볼 때.
    def verify_access_token(token)
      AccessClaims.read(verify_signed(token, 'at+jwt'))
    end

    # licenseToken(license+jwt)을 검증한다. `min_generation` — 같은 sub · device_id에서 판매자 서버가 이미 본 가장 큰 세대번호(0이면 보지 않는다).
    # 그보다 작으면 GENERATION_REGRESSED.
    def verify_license_token(token, min_generation: 0)
      claims = LicenseClaims.read(verify_signed(token, 'license+jwt'))
      if min_generation.positive? && claims.generation < min_generation
        raise Error.new(Codes::GENERATION_REGRESSED, "세대번호 #{claims.generation} < 이미 본 #{min_generation}")
      end

      claims
    end

    private

    # 9절 1 ~ 4를 통과한 페이로드
    def verify_signed(token, typ)
      parts = token.to_s.split('.', -1)
      raise invalid('JWT 형식이 아니다') unless parts.size == 3

      header = json(base64url(parts[0]))
      payload = json(base64url(parts[1]))
      signature = base64url(parts[2])
      raise invalid('JWT를 읽지 못했다') unless header.is_a?(Hash) && payload.is_a?(Hash) && signature

      raise invalid('alg가 EdDSA가 아니다') unless header['alg'] == 'EdDSA'
      raise invalid("typ가 #{typ}가 아니다") unless header['typ'] == typ

      kid = header['kid']
      raise invalid('kid가 없다') unless kid.is_a?(String) && !kid.empty?
      raise invalid('서명이 맞지 않는다') unless ed25519_verify(key_for(kid), signature, "#{parts[0]}.#{parts[1]}")
      raise invalid('iss가 다르다') unless payload['iss'] == discovery[:issuer]
      raise invalid('aud가 이 client_id가 아니다') unless payload['aud'] == @client_id

      exp = payload['exp']
      raise invalid('만료된 토큰') if !exp.is_a?(Integer) || exp <= @clock.call - Rules::TOKEN_CLOCK_LEEWAY_SEC

      payload
    end

    def ed25519_verify(public_key, signature, message)
      return false unless signature.bytesize == 64

      OpenSSL::PKey.read(SPKI_PREFIX + public_key).verify(nil, signature, message)
    rescue OpenSSL::PKey::PKeyError
      false
    end

    # 9.1절 — 지난 캐시는 쓰지 않는다 · 모르는 kid는 1분에 한 번만 다시 받는다
    def key_for(kid)
      now = @clock.call
      set = @mutex.synchronize { @key_set } || cached_keys
      set = fetch_keys if set.nil? || now >= set[:expires_at]
      return set[:keys][kid] if set[:keys].key?(kid)
      raise invalid("모르는 kid #{kid}") if now - set[:fetched_at] < Rules::JWKS_UNKNOWN_KID_REFETCH_MIN_INTERVAL_SEC

      fetch_keys[:keys].fetch(kid) { raise invalid("모르는 kid #{kid}") }
    end

    def fetch_keys
      headers, body = get(discovery[:jwks_uri])
      keys = {}
      Array(body['keys']).each do |jwk|
        next unless jwk.is_a?(Hash) && jwk['kty'] == 'OKP' && jwk['crv'] == 'Ed25519'

        kid = jwk['kid']
        raw = jwk['x'].is_a?(String) ? base64url(jwk['x']) : nil
        keys[kid] = raw.freeze if kid.is_a?(String) && !kid.empty? && raw&.bytesize == 32
      end
      max_age = headers['cache-control'].to_s[/(?:\A|,)\s*max-age=(\d+)/, 1]&.to_i || Rules::JWKS_DEFAULT_MAX_AGE_SEC
      now = @clock.call.to_f
      # 통째로 바꾼다 — 빠진 키는 더는 믿지 않는다
      set = { keys: keys.freeze, fetched_at: now, expires_at: now + max_age }.freeze
      @mutex.synchronize { @key_set = set }
      store('jwks', { 'keys' => keys.transform_values { |raw| [raw].pack('m0').tr('+/', '-_').delete('=') },
                      'fetchedAt' => now, 'expiresAt' => now + max_age },
            max_age + Rules::JWKS_UNKNOWN_KID_REFETCH_MIN_INTERVAL_SEC)
      set
    end

    # 처음 한 번 받아 둔다. issuer가 base_url과 다르면 CONFIGURATION (명세 4절)
    def discovery
      found = @mutex.synchronize { @discovery }
      return found if found

      cached = cached_value('discovery')
      found = if cached.is_a?(Hash) && cached['issuer'].is_a?(String) && cached['jwks_uri'].is_a?(String)
                { issuer: cached['issuer'], jwks_uri: cached['jwks_uri'] }
              else
                fetch_discovery
              end
      @mutex.synchronize { @discovery = found.freeze }
    end

    def fetch_discovery
      _, body = get("#{@base_url}/.well-known/openid-configuration")
      issuer = body['issuer']
      jwks_uri = body['jwks_uri']
      raise Error.new(Codes::PROTOCOL_ERROR, '발견 문서에 issuer · jwks_uri가 없다') unless issuer.is_a?(String) && jwks_uri.is_a?(String)
      if issuer.chomp('/') != @base_url
        raise Error.new(Codes::CONFIGURATION, "발견 문서의 issuer(#{issuer})가 base_url(#{@base_url})과 다르다")
      end

      store('discovery', { 'issuer' => issuer, 'jwks_uri' => jwks_uri }, 86_400)
      { issuer: issuer, jwks_uri: jwks_uri }
    end

    # 2xx면 [헤더, JSON], 아니면 에러
    def get(url)
      status, headers, body = begin
        @http.call(url)
      rescue Error
        raise
      rescue StandardError => e
        raise Error.new(Codes::NETWORK_ERROR, "API에 연결하지 못했다: #{e.class}")
      end
      parsed = json(body)
      if (200..299).cover?(status)
        raise Error.new(Codes::PROTOCOL_ERROR, '응답 본문이 JSON이 아니다', http_status: status) unless parsed.is_a?(Hash)

        return [headers, parsed]
      end
      if parsed.is_a?(Hash) && parsed['code'].is_a?(String) && parsed['message'].is_a?(String)
        raise Error.new(parsed['code'], parsed['message'], http_status: status)
      end

      code = if status >= 500 then Codes::INTERNAL_ERROR
             elsif status == 429 then Codes::RATE_LIMITED
             else Codes::PROTOCOL_ERROR
             end
      raise Error.new(code, "HTTP #{status}", http_status: status)
    end

    def cached_keys
      value = cached_value('jwks')
      return nil unless value.is_a?(Hash) && value['fetchedAt'].is_a?(Numeric) && value['expiresAt'].is_a?(Numeric)

      keys = value['keys'].to_h.filter_map do |kid, x|
        raw = x.is_a?(String) ? base64url(x) : nil
        [kid.to_s, raw.freeze] if raw&.bytesize == 32
      end.to_h
      set = { keys: keys.freeze, fetched_at: value['fetchedAt'].to_f, expires_at: value['expiresAt'].to_f }.freeze
      @mutex.synchronize { @key_set = set }
    end

    def cache_key(name) = "#{CACHE_PREFIX}#{name}.#{Digest::MD5.hexdigest(@base_url)}"

    def cached_value(name)
      return nil unless @cache

      raw = @cache.read(cache_key(name))
      raw.is_a?(String) ? json(raw) : nil
    end

    def store(name, value, ttl)
      @cache&.write(cache_key(name), JSON.generate(value), expires_in: ttl)
    end

    def invalid(message) = Error.new(Codes::TOKEN_INVALID, message)

    def json(text)
      text.is_a?(String) ? JSON.parse(text) : nil
    rescue JSON::ParserError
      nil
    end

    def base64url(text)
      return nil unless text.match?(/\A[A-Za-z0-9_-]*\z/)

      padded = text.tr('-_', '+/')
      padded += '=' * ((4 - (padded.length % 4)) % 4)
      padded.unpack1('m0')
    rescue ArgumentError
      nil
    end
  end
end
