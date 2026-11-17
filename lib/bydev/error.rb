# frozen_string_literal: true

module Bydev
  # 실패 하나 — `code`로 분기한다(`Bydev::Codes`). 메시지는 보여 주기만 한다.
  class Error < StandardError
    attr_reader :code, :http_status

    def initialize(code, message, http_status: nil)
      super(message)
      @code = code
      @http_status = http_status
    end
  end
end
