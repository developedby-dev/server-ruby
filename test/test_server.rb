# frozen_string_literal: true

require 'minitest/autorun'
require 'json'
require 'socket'
require 'bydev-server'

def b64url(raw) = [raw].pack('m0').tr('+/', '-_').delete('=')

# 웹훅 — 안내서 11장의 서명 예시(TS · Go · .NET · Kotlin · Python · PHP 시험과 같은 값)
class WebhookTest < Minitest::Test
  SECRET = 'whsec_/MU12AiKByBoT7xt+p81N/uKdp/WxQRb'
  ID = 'evt_01J9MC4D6E8F0G2H4J6K8M0N2P'
  SENT = 1_791_295_205
  BODY = '{"id":"evt_01J9MC4D6E8F0G2H4J6K8M0N2P","type":"build.review_completed","occurredAt":"2026-10-06T14:00:00Z","mode":"LIVE","simulated":false,"data":{"build":{"id":"build_01J9M4D6F8H0J2K4M6N8P0R2S4","productId":"prod_01J9KZ3F7W2X8YQ4N6M5R1TBCD","version":"1.4.2","reviewedAt":"2026-10-06T13:58:00Z","result":"APPROVED"}}}'
  SIGNATURE = 'v1,vmsiq2HY4gik/WNJjXJzuESzXAjJgr8Vi13SKwwhgEo='

  def headers(sig) = { 'Webhook-Id' => ID, 'Webhook-Timestamp' => SENT.to_s, 'Webhook-Signature' => sig }

  def verify(secrets: [SECRET], headers: headers(SIGNATURE), body: BODY, now: SENT)
    Bydev.verify_webhook(secrets: secrets, headers: headers, raw_body: body, now: now)
  end

  def assert_code(code, &)
    error = assert_raises(Bydev::Error, &)
    assert_equal code, error.code
  end

  def test_guide_example
    assert_equal Bydev::WebhookVerification.new(id: ID, timestamp: SENT), verify(now: SENT + 10)
    # Rack env 모양(HTTP_ 접두사 · 밑줄)
    rack = { 'HTTP_WEBHOOK_ID' => ID, 'HTTP_WEBHOOK_TIMESTAMP' => SENT.to_s, 'HTTP_WEBHOOK_SIGNATURE' => SIGNATURE }
    assert_equal ID, verify(headers: rack).id
  end

  def test_rotation
    verify(headers: headers("v1,AAAA #{SIGNATURE}"))
    verify(secrets: ['whsec_AAAAAAAAAAAAAAAAAAAAAAAA', SECRET])
  end

  def test_rejects_tampering_replay_and_missing_headers
    assert_code(Bydev::Codes::WEBHOOK_INVALID) { verify(body: "#{BODY} ") }
    assert_code(Bydev::Codes::WEBHOOK_INVALID) { verify(now: SENT + 301) }
    assert_code(Bydev::Codes::WEBHOOK_INVALID) { verify(now: SENT - 301) }
    assert_code(Bydev::Codes::WEBHOOK_INVALID) { verify(headers: { 'webhook-id' => ID }) }
    assert_code(Bydev::Codes::WEBHOOK_INVALID) { verify(headers: headers("v2,#{SIGNATURE[3..]}")) }
    # 접두사 없는 시크릿은 설정 실수
    assert_code(Bydev::Codes::CONFIGURATION) { verify(secrets: ['/MU12AiKByBoT7xt+p81N/uKdp/WxQRb']) }
  end
end

BASE = 'https://api.example.test'
CLIENT = 'cli_01J9M0Y6X4N3Q8ZD5R2KT7VCPW'
NOW = 1_791_295_205

def raw_public(key) = key.public_to_der[-32..]

def mint(key, kid, typ, claims, alg: 'EdDSA')
  input = "#{b64url(JSON.generate({ alg: alg, typ: typ, kid: kid }))}.#{b64url(JSON.generate(claims))}"
  "#{input}.#{b64url(key.sign(nil, input))}"
end

def access(**over)
  { iss: BASE, sub: 'psub_01J9M5X3W1V9T7S5R3Q1P9N7M5', aud: CLIENT, client_id: CLIENT, scope: 'entitlement.read',
    iat: NOW, exp: NOW + 3600, jti: 'at_rb0001' }.merge(over)
end

def license(generation, over = {})
  { iss: BASE, sub: 'psub_01J9M5X3W1V9T7S5R3Q1P9N7M5', aud: CLIENT, product_id: 'prod_01J9KZ3F7W2X8YQ4N6M5R1TBCD',
    device_id: 'dev_01J9M0Z8Y7X6W5V4T3S2R1Q0P9', sid: 'sess_01J9M2P8Q7R6S5T4V3W2X1Y0Z9', generation: generation,
    iat: NOW, exp: NOW + 600 }.merge(over)
end

# 가짜 API — 발견 문서 · JWKS
class FakeApi
  attr_accessor :keys, :issuer
  attr_reader :hits

  def initialize(keys)
    @keys = keys
    @issuer = BASE
    @hits = []
  end

  def call(url)
    path = URI(url).path
    @hits << path
    return [200, {}, JSON.generate({ issuer: @issuer, jwks_uri: "#{BASE}/.well-known/jwks.json" })] if path.end_with?('openid-configuration')

    jwks = @keys.map { |kid, key| { kty: 'OKP', crv: 'Ed25519', kid: kid, x: b64url(raw_public(key)) } }
    jwks << { kty: 'RSA', kid: 'rsa-k1', n: 'x', e: 'AQAB' } # 다른 키는 버린다
    [200, { 'cache-control' => 'public, max-age=300' }, JSON.generate({ keys: jwks })]
  end
end

# Rails 캐시 모양의 메모리 캐시
class MemoryCache
  attr_reader :items

  def initialize = @items = {}
  def read(key) = @items[key]
  def write(key, value, expires_in: nil) = @items[key] = value
end

class ServerVerifierTest < Minitest::Test
  def setup
    @key = OpenSSL::PKey.generate_key('ED25519')
    @api = FakeApi.new({ 'srv-k1' => @key })
    @offset = 0
    @verifier = Bydev::ServerVerifier.new(base_url: "#{BASE}/", client_id: CLIENT, http: @api, clock: -> { NOW + @offset })
  end

  def assert_code(code, &)
    error = assert_raises(Bydev::Error, &)
    assert_equal code, error.code
  end

  def test_verifies_access_tokens
    claims = @verifier.verify_access_token(mint(@key, 'srv-k1', 'at+jwt', access))
    assert_equal Bydev::AccessClaims.new(iss: BASE, sub: 'psub_01J9M5X3W1V9T7S5R3Q1P9N7M5', aud: CLIENT, client_id: CLIENT,
                                         scope: 'entitlement.read', iat: NOW, exp: NOW + 3600, jti: 'at_rb0001'), claims
    assert_code(Bydev::Codes::TOKEN_INVALID) { @verifier.verify_access_token(mint(@key, 'srv-k1', 'at+jwt', access(aud: 'cli_other_client_00000000'))) }
    assert_code(Bydev::Codes::TOKEN_INVALID) { @verifier.verify_access_token(mint(@key, 'srv-k1', 'license+jwt', access)) }
    assert_code(Bydev::Codes::TOKEN_INVALID) { @verifier.verify_access_token(mint(@key, 'srv-k1', 'at+jwt', access, alg: 'RS256')) }
    assert_code(Bydev::Codes::TOKEN_INVALID) { @verifier.verify_access_token(mint(@key, 'srv-k1', 'at+jwt', access(exp: NOW - 61))) }
    @verifier.verify_access_token(mint(@key, 'srv-k1', 'at+jwt', access(exp: NOW - 30))) # 허용 안
    forged = mint(OpenSSL::PKey.generate_key('ED25519'), 'srv-k1', 'at+jwt', access)
    assert_code(Bydev::Codes::TOKEN_INVALID) { @verifier.verify_access_token(forged) }
    assert_code(Bydev::Codes::TOKEN_INVALID) { @verifier.verify_access_token('a.b') }
  end

  def test_jwks_cache_rules
    # 모르는 kid — 1분 안에는 다시 받지 않는다
    assert_code(Bydev::Codes::TOKEN_INVALID) { @verifier.verify_access_token(mint(@key, 'srv-k9', 'at+jwt', access)) }
    assert_equal ['/.well-known/openid-configuration', '/.well-known/jwks.json'], @api.hits
    # 1분 뒤 모르는 kid는 다시 받는다 — 새 키가 실렸다
    second = OpenSSL::PKey.generate_key('ED25519')
    @api.keys = { 'srv-k2' => second }
    @offset = 61
    @verifier.verify_access_token(mint(second, 'srv-k2', 'at+jwt', access))
    # 통째로 바꿨다 — 빠진 srv-k1은 더는 믿지 않는다
    assert_code(Bydev::Codes::TOKEN_INVALID) { @verifier.verify_access_token(mint(@key, 'srv-k1', 'at+jwt', access)) }
    # max-age가 지나면 다시 받는다
    @api.keys = { 'srv-k1' => @key }
    before = @api.hits.size
    @offset = 61 + 301
    @verifier.verify_access_token(mint(@key, 'srv-k1', 'at+jwt', access(exp: NOW + 7200)))
    assert_equal before + 1, @api.hits.size
  end

  def test_license_tokens_and_generation
    assert_equal 3, @verifier.verify_license_token(mint(@key, 'srv-k1', 'license+jwt', license(3)), min_generation: 3).generation
    assert_nil @verifier.verify_license_token(mint(@key, 'srv-k1', 'license+jwt', license(3))).build_id
    built = license(3, build_id: 'build_01J9M4D6F8H0J2K4M6N8P0R2S4')
    assert_equal 'build_01J9M4D6F8H0J2K4M6N8P0R2S4',
                 @verifier.verify_license_token(mint(@key, 'srv-k1', 'license+jwt', built)).build_id
    assert_code(Bydev::Codes::GENERATION_REGRESSED) do
      @verifier.verify_license_token(mint(@key, 'srv-k1', 'license+jwt', license(2)), min_generation: 3)
    end
  end

  def test_configuration_and_transport_errors
    @api.issuer = 'https://evil.example.test'
    assert_code(Bydev::Codes::CONFIGURATION) { @verifier.verify_access_token(mint(@key, 'srv-k1', 'at+jwt', access)) }
    down = Bydev::ServerVerifier.new(base_url: BASE, client_id: CLIENT, http: ->(_) { [503, {}, 'down'] }, clock: -> { NOW })
    assert_code(Bydev::Codes::INTERNAL_ERROR) { down.verify_access_token(mint(@key, 'srv-k1', 'at+jwt', access)) }
    broken = Bydev::ServerVerifier.new(base_url: BASE, client_id: CLIENT, http: ->(_) { raise IOError }, clock: -> { NOW })
    assert_code(Bydev::Codes::NETWORK_ERROR) { broken.verify_access_token(mint(@key, 'srv-k1', 'at+jwt', access)) }
  end

  def test_shared_cache_across_instances
    cache = MemoryCache.new
    first = Bydev::ServerVerifier.new(base_url: BASE, client_id: CLIENT, http: @api, clock: -> { NOW }, cache: cache)
    first.verify_access_token(mint(@key, 'srv-k1', 'at+jwt', access))
    other = Bydev::ServerVerifier.new(base_url: BASE, client_id: CLIENT, http: @api, clock: -> { NOW + 10 }, cache: cache)
    other.verify_access_token(mint(@key, 'srv-k1', 'at+jwt', access))
    assert_equal 2, @api.hits.size # 다음 프로세스는 받지 않는다
    late = Bydev::ServerVerifier.new(base_url: BASE, client_id: CLIENT, http: @api, clock: -> { NOW + 400 }, cache: cache)
    late.verify_access_token(mint(@key, 'srv-k1', 'at+jwt', access))
    assert_equal 3, @api.hits.size # max-age가 지나면 JWKS만 다시
  end
end

# 실제 HTTP — 표준 TCPServer로 띄운 작은 서버에 기본 전송(Net::HTTP)
class RealHttpTest < Minitest::Test
  def setup
    @key = OpenSSL::PKey.generate_key('ED25519')
    @server = TCPServer.new('127.0.0.1', 0)
    @base = "http://127.0.0.1:#{@server.addr[1]}"
    x = b64url(raw_public(@key))
    base = @base
    @thread = Thread.new do
      loop do
        client = @server.accept
        path = client.gets.to_s.split[1].to_s
        nil while (line = client.gets) && line != "\r\n"
        status, headers, body =
          case path
          when '/.well-known/openid-configuration' then [200, {}, JSON.generate({ issuer: base, jwks_uri: "#{base}/.well-known/jwks.json" })]
          when '/.well-known/jwks.json'
            [200, { 'Cache-Control' => 'public, max-age=300' }, JSON.generate({ keys: [{ kty: 'OKP', crv: 'Ed25519', kid: 'srv-k1', x: x }] })]
          when '/redirect' then [302, { 'Location' => '/.well-known/jwks.json' }, '']
          else [404, {}, JSON.generate({ code: 'PRODUCT_NOT_FOUND', message: '없음' })]
          end
        head = headers.merge('Content-Type' => 'application/json', 'Content-Length' => body.bytesize.to_s, 'Connection' => 'close')
        client.write("HTTP/1.1 #{status} X\r\n#{head.map { |k, v| "#{k}: #{v}\r\n" }.join}\r\n#{body}")
        client.close
      rescue IOError, Errno::EBADF
        break
      end
    end
  end

  def teardown
    @server.close
    @thread.join(1)
  end

  def test_default_transport
    now = Time.now.to_i
    token = mint(@key, 'srv-k1', 'at+jwt', access(iss: @base, iat: now, exp: now + 600))
    assert_equal 'psub_01J9M5X3W1V9T7S5R3Q1P9N7M5', Bydev::ServerVerifier.new(base_url: @base, client_id: CLIENT).verify_access_token(token).sub
    status, headers, = Bydev::Http.get("#{@base}/redirect")
    assert_equal [302, '/.well-known/jwks.json'], [status, headers['location']] # 리다이렉트를 따라가지 않는다 · 헤더는 소문자
    assert_equal 404, Bydev::Http.get("#{@base}/nope").first
    error = assert_raises(Bydev::Error) { Bydev::Http.get('http://127.0.0.1:1/') }
    assert_equal Bydev::Codes::NETWORK_ERROR, error.code
  end
end
