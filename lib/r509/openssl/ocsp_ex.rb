# vim: set sts=2 ts=2 sw=2 et:
require 'r509/openssl/pkey_ex'

module OpenSSL::OCSP
  module BasicResponseSigningExtension
    # Use the internal signer to get everything set up, then resign with our digest
    def sign(signer_cert, signer_key, certificates=nil, flags=nil, digest=OpenSSL::Digest::SHA1.new)
      super(signer_cert, signer_key, certificates, flags)
      signed_der = signer_key.sign_x509_der!(digest, self.to_der)
      self.class.from_der(signed_der)
    end

    # Create an alias to make reponds_to? a viable test for this enhancement
    alias_method :sign_with_digest, :sign

    def to_der
      # To get the DER, we create a response, get the DER,
      # decode the DER to ASN.1, grab the basic member, and get the DER of that
      
      temp_status = OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
      res = OpenSSL::OCSP::Response.create(temp_status, self)
      asn = OpenSSL::ASN1.decode(res.to_der)
      
      # OCSPResponse.(explicit).responseBytes.response is an octet string of DER
      asn.value[1].value[0].value[1].value
    end
  end 
  class BasicResponse
    prepend OpenSSL::OCSP::BasicResponseSigningExtension

    def self.from_der(bder)
      # Given DER, manually build a OCSPResponse, parse it, and get the basicResponse
      response_bytes = OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::ObjectId.new("1.3.6.1.5.5.7.48.1.1"),
        OpenSSL::ASN1::OctetString.new(bder)
      ])

      # Note that Explicit tagging requires wrapping the data in an array
      # This is not documented well, but will raise an error if you do not
      ocsp_response = OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::Enumerated.new(OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL),
        OpenSSL::ASN1::ASN1Data.new([response_bytes], 0, :CONTEXT_SPECIFIC)
      ])
      res_der = ocsp_response.to_der
      res = OpenSSL::OCSP::Response.new(res_der)
      res.basic
    end 
  end
end 
