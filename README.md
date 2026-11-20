# 데브 서버 도우미: Ruby

판매자 서버에서 쓰는 두 기능만 담은 작은 젬입니다. Rails, Sinatra, Hanami 같은 Ruby 서버에서 웹훅 서명을 검증하고, 토큰(access_token,
licenseToken)을 검증합니다.

로그인이나 세션 같은 데스크톱 앱용 기능은 들어 있지 않습니다. 의존성은 표준 라이브러리(`openssl`, `json`, `net/http`)뿐입니다.

| 지원 | 버전 |
|---|---|
| 동작 명세 | 1.2.0 (12절 서버 도우미) |
| Ruby | 3.3 이상(Ed25519를 쓰려면 OpenSSL 1.1.1 이상) |

젬 이름은 `bydev-server`입니다. 지금 RubyGems에 있는 0.x 판은 이름을 먼저 등록하려고 낸 미리보기입니다. 1.0.0은 서비스 오픈과 함께 내며, 그 전에는
호환되지 않는 변경이 있을 수 있습니다. 판매하는 서비스에는 1.0.0 이상을 써 주세요.

## 빠른 시작

```ruby
require 'bydev-server'

# 웹훅: 받은 본문 그대로 검증하세요. JSON으로 읽었다가 다시 만든 문자열로는 서명이 맞지 않습니다. 시크릿을 교체하는 중이면 둘 다 넘기세요
event = Bydev.verify_webhook(secrets: [ENV.fetch('BYDEV_WEBHOOK_SECRET')], headers: request.headers, raw_body: request.raw_post)
# event.id로 중복 수신을 걸러 주세요. 검증에 실패하면 Bydev::Error가 발생합니다(code == Bydev::Codes::WEBHOOK_INVALID)

# 앱이 보낸 access_token을 검증합니다. 인스턴스 하나를 오래 두고 쓰세요. 여러 프로세스가 JWKS를 함께 쓰려면 Rails 캐시를 넘기세요
VERIFIER = Bydev::ServerVerifier.new(base_url: 'https://api.developedby.dev',
                                     client_id: 'cli_01J9M0Y6X4N3Q8ZD5R2KT7VCPW', cache: Rails.cache)
claims = VERIFIER.verify_access_token(bearer_token) # claims.sub는 이 판매자 전용 가명 식별자입니다
```

## 사용 조건

- **실패**하면 `Bydev::Error`가 발생합니다. 분기는 `code`로 해 주세요.

  값은 `Bydev::Codes::*`에 있으며, `WEBHOOK_INVALID`, `TOKEN_INVALID`,
  `GENERATION_REGRESSED`, `NETWORK_ERROR` 등이 있습니다.
- **헤더**: 헤더 이름의 대소문자를 가리지 않으며, Rack env 형식(`HTTP_WEBHOOK_ID`)으로 넘겨도 됩니다.
- **JWKS 캐시**: 응답의 `Cache-Control: max-age` 동안만 보관합니다. 처음 보는 `kid`가 오면 마지막으로 받은 지 1분이 지났을 때만 다시 받습니다.

  인스턴스 하나를 여러 스레드에서 함께 써도 됩니다.
- **licenseToken**: `verify_license_token(token, min_generation:)`을 사용해 주세요. 지금까지 본 가장 큰 세대번호(세션을 새로 얻거나 인수할 때마다 커지는
  번호)보다 작은 세대번호의 토큰은 거부합니다.
- **HTTP**: 표준 Net::HTTP를 쓰며, 리다이렉트는 따라가지 않습니다. 프록시가 필요하면 `http:` 인자에 `call(url) → [상태, 소문자 헤더, 본문]` 모양의
  객체를 전달해 주세요.
- 라이선스는 MIT 또는 Apache-2.0입니다.

## 출처 확인

이 꾸러미는 공개 저장소 `developedby-dev/server-ruby`의 GitHub Actions가 판 태그에서 짓고 올립니다. RubyGems에 올린 `.gem`에는 GitHub 출처 증명이 있습니다. 받은 파일을 `gh attestation verify <파일> --repo developedby-dev/server-ruby`로 확인할 수 있습니다.

## 개발

| 명령 | 하는 일 |
|---|---|
| `ruby -w -Ilib -Itest test/test_server.rb` | minitest로 시험을 돌립니다. 웹훅 안내서의 예시, 토큰 검증, JWKS 캐시 규칙, 표준 TCPServer로 띄운 실제 HTTP 통신을 확인합니다. |
| `pnpm sdk:check ruby` | 같은 시험을 돌립니다. |

`lib/bydev/generated.rb`는 생성된 파일이며, `pnpm --filter @bydev/sdk-codegen generate`로 다시 만듭니다.
