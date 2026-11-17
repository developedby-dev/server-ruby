# frozen_string_literal: true

require 'net/http'
require 'uri'

module Bydev
  # 기본 HTTP GET — 표준 Net::HTTP. 리다이렉트를 따라가지 않는다(Net::HTTP는 원래 따라가지 않는다) · 시간 초과는 `Rules::HTTP_TIMEOUT_SEC`.
  # 프록시 · 인증서 고정이 필요하면 `ServerVerifier`에 같은 모양의 호출 가능한 것을 준다.
  module Http
    # @return [Array(Integer, Hash{String=>String}, String)] 상태 · 소문자 헤더 · 본문
    def self.get(url)
      uri = URI(url)
      response = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https',
                                                     open_timeout: Rules::HTTP_TIMEOUT_SEC,
                                                     read_timeout: Rules::HTTP_TIMEOUT_SEC) do |http|
        http.get(uri.request_uri, 'Accept' => 'application/json', 'User-Agent' => "bydev-ruby-server/#{VERSION}")
      end
      [response.code.to_i, response.each_header.to_h { |k, v| [k.downcase, v] }, response.body.to_s]
    rescue SystemCallError, IOError, SocketError, Timeout::Error, OpenSSL::SSL::SSLError => e
      raise Error.new(Codes::NETWORK_ERROR, "API에 연결하지 못했다: #{e.class}")
    end
  end
end
