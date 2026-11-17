# frozen_string_literal: true

require 'openssl'

module Bydev
  # 검증된 웹훅의 id와 시각(Unix 초) — 중복 수신은 id로 거른다.
  WebhookVerification = Data.define(:id, :timestamp)

  # 웹훅 서명 검증 (명세 12절 · 안내서 11장 — Standard Webhooks v1).
  #
  # `raw_body`는 **받은 그대로의 본문**이다(Rails `request.raw_post` · Rack `request.body.read`) — JSON으로 읽었다가 다시 만든 글자는 서명이 맞지
  # 않는다. 시크릿을 교체하는 중이면 둘 다 넘긴다. 헤더 이름의 대소문자 · `HTTP_` 접두사(Rack env)는 가리지 않는다.
  def self.verify_webhook(secrets:, headers:, raw_body:, now: Time.now.to_i)
    lowered = headers.to_h.to_h { |name, value| [name.to_s.downcase.delete_prefix('http_').tr('_', '-'), Array(value).first.to_s] }
    id = lowered.fetch('webhook-id', '')
    timestamp = lowered.fetch('webhook-timestamp', '')
    signatures = lowered.fetch('webhook-signature', '')
    if id.empty? || timestamp.empty? || signatures.empty?
      raise Error.new(Codes::WEBHOOK_INVALID, '웹훅 헤더(webhook-id · webhook-timestamp · webhook-signature)가 없다')
    end
    if !timestamp.match?(/\A\d+\z/) || (now - timestamp.to_i).abs > Rules::WEBHOOK_TOLERANCE_SEC
      raise Error.new(Codes::WEBHOOK_INVALID, '웹훅 시각이 허용 범위 밖이다 — 재전송 공격일 수 있다')
    end

    candidates = signatures.split(' ').filter_map do |entry|
      version, value = entry.split(',', 2)
      next unless version == Rules::WEBHOOK_SIGNATURE_VERSION && value && !value.empty?

      begin
        value.unpack1('m0')
      rescue ArgumentError
        nil
      end
    end
    signed = "#{id}.#{timestamp}.".b + raw_body.to_s.b
    secrets.each do |secret|
      unless secret.start_with?(Rules::WEBHOOK_SECRET_PREFIX)
        raise Error.new(Codes::CONFIGURATION, "웹훅 시크릿은 #{Rules::WEBHOOK_SECRET_PREFIX}로 시작한다")
      end

      key = begin
        secret.delete_prefix(Rules::WEBHOOK_SECRET_PREFIX).unpack1('m0')
      rescue ArgumentError
        raise Error.new(Codes::CONFIGURATION, '웹훅 시크릿을 읽지 못했다')
      end
      expected = OpenSSL::HMAC.digest('SHA256', key, signed)
      if candidates.any? { |candidate| candidate.bytesize == expected.bytesize && OpenSSL.fixed_length_secure_compare(candidate, expected) }
        return WebhookVerification.new(id: id, timestamp: timestamp.to_i)
      end
    end
    raise Error.new(Codes::WEBHOOK_INVALID, '웹훅 서명이 맞지 않는다')
  end
end
