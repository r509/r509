require 'openssl'
require 'r509/exceptions'
require 'r509/config'

# OCSP module
module R509::OCSP
  # builds OCSP responses
  class Response
    # @param ocsp_response [OpenSSL::OCSP::Response]
    def initialize(ocsp_response)
      unless ocsp_response.kind_of?(OpenSSL::OCSP::Response)
        raise R509::R509Error, 'You must pass an OpenSSL::OCSP::Response object to the constructor. See R509::OCSP::Response.parse if you are trying to parse'
      end
      @ocsp_response = ocsp_response
    end
    # @param [String,OpenSSL::OCSP::Response] ocsp_string parses an existing response
    # @return [R509::OCSP::Response]
    def self.parse(ocsp_string)
      if ocsp_string.nil?
        raise R509::R509Error, 'You must pass a DER encoded OCSP response to this method'
      end
      R509::OCSP::Response.new(OpenSSL::OCSP::Response.new(ocsp_string))
    end

    # @return [OpenSSL::OCSP] response status of this response
    def status
      @ocsp_response.status
    end

    # @return [String] der encoded string
    def to_der
      @ocsp_response.to_der
    end

    # @return [OpenSSL::OCSP::BasicResponse]
    def basic
      @ocsp_response.basic
    end

    # @param [Array<OpenSSL::X509::Certificate>,OpenSSL::X509::Certificate] certs A cert or array of certs to verify against
    # @return [Boolean] true if the response is valid according to the given root
    def verify(certs)
      store = OpenSSL::X509::Store.new
      if certs.kind_of?(Array)
        stack = certs
        certs.each do |cert|
          store.add_cert(cert)
        end
      else
        stack = [certs]
        store.add_cert(certs)
      end

      # suppress verbosity since #verify will output a warning if it does not match
      # as well as returning false. we just want the boolean
      original_verbosity = $VERBOSE
      $VERBOSE = nil
      # still a bit unclear on why we add to store and pass in array to verify
      result = @ocsp_response.basic.verify(stack, store)
      $VERBOSE = original_verbosity
      return result
    end

    # @param [OpenSSL::OCSP::Request] ocsp_request the OCSP request whose nonce to check
    # @return [R509::OCSP::Request::Nonce::CONSTANT] the status code of the nonce check
    def check_nonce(ocsp_request)
      ocsp_request.check_nonce(@ocsp_response.basic)
    end
  end

  # holds OCSP request related items
  module Request
    # contains constants r509 uses for OCSP responses
    module Nonce
      # these values are defined at
      # http://www.ruby-doc.org/stdlib-1.9.3/libdoc/openssl/rdoc/OpenSSL/OCSP/Request.html
      # nonce is present and matches
      PRESENT_AND_EQUAL = 1

      # nonce is missing in request and response
      BOTH_ABSENT = 2

      # nonce is present in response only
      RESPONSE_ONLY = 3

      # nonce is in both request and response, but does not match
      NOT_EQUAL = 0

      # nonce is present in request only
      REQUEST_ONLY = -1
    end
  end
end
