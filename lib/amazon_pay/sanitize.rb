# rubocop:disable Metrics/MethodLength, Metrics/LineLength

module AmazonPay
  # Removes PII and other sensitive data for the logger
  class Sanitize
    def initialize(input_data)
      @copy = input_data ? input_data.dup.force_encoding("UTF-8") : ''
    end

    def sanitize_request_data
      # Array of item to remove

      patterns = %w[
        Buyer
        PhysicalDestination
        BillingAddress
        AuthorizationBillingAddress
        SellerNote
        SellerAuthorizationNote
        SellerCaptureNote
        SellerRefundNote
      ]

      patterns.each do |s|
        @copy.gsub!(/([?|&]#{s}=)[^\&]+/mu, s + '=*REMOVED*')
      end

      @copy
    end

    def sanitize_response_data
      # Array of item to remove

      patterns = []
      patterns.push(%r{(?<=<Buyer>).*(?=<\/Buyer>)}u)
      patterns.push(%r{(?<=<PhysicalDestination>).*(?=<\/PhysicalDestination>)}mu)
      patterns.push(%r{(?<=<BillingAddress>).*(?=<\/BillingAddress>)}u)
      patterns.push(%r{(?<=<SellerNote>).*(?=<\/SellerNote>)}u)
      patterns.push(%r{(?<=<AuthorizationBillingAddress>).*(?=<\/AuthorizationBillingAddress>)}u)
      patterns.push(%r{(?<=<SellerAuthorizationNote>).*(?=<\/SellerAuthorizationNote>)}u)
      patterns.push(%r{(?<=<SellerCaptureNote>).*(?=<\/SellerCaptureNote>)}u)
      patterns.push(%r{(?<=<SellerRefundNote>).*(?=<\/SellerRefundNote>)}u)

      patterns.each do |s|
        @copy.gsub!(s, '*REMOVED*')
      end

      @copy
    end
  end
end
