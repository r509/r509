require 'openssl'
require 'r509/Exceptions'
require 'r509/Config'
require 'r509/HelperClasses'

module R509::Ocsp
    # A class for signing OCSP responses
    class Signer

        # @option options [Boolean] :copy_nonce
        # @option options [Array<R509::Config>] array of configs corresponding to all
        # possible OCSP issuance roots that we want to issue OCSP responses for
        def initialize(options)
            if options.has_key?(:validity_checker)
                @validity_checker = options[:validity_checker]
            else
                @validity_checker = R509::Validity::DefaultChecker.new
            end
            @request_checker = Helper::RequestChecker.new(options[:configs], @validity_checker)
            @response_signer = Helper::ResponseSigner.new(options)
        end

        def check_request(request)
            @request_checker.check_request(request)
        end

        def sign_response(statuses)
            @response_signer.sign_response(statuses)
        end
    end
end

module R509::Ocsp::Request
    module Nonce
        PRESENT_AND_EQUAL = 1
        BOTH_ABSENT = 2
        RESPONSE_ONLY = 3
        NOT_EQUAL = 0
        REQUEST_ONLY = -1
    end
end

module R509::Ocsp
    class Response
        # @param ocsp_response [OpenSSL::OCSP::Response]
        def initialize(ocsp_response)
            if not ocsp_response.kind_of?(OpenSSL::OCSP::Response)
                raise R509::R509Error, 'You must pass an OpenSSL::OCSP::Response object to the constructor. See R509::Ocsp::Response#parse if you are trying to parse'
            end
            @ocsp_response = ocsp_response
        end

        def self.parse(ocsp_string)
            if ocsp_string.nil?
                raise R509::R509Error, 'You must pass a DER encoded OCSP response to this method'
            end
            R509::Ocsp::Response.new(OpenSSL::OCSP::Response.new(ocsp_string))
        end

        # @return [OpenSSL::OCSP] response status of this response
        def status
            @ocsp_response.status
        end

        # @return [String] der encoded string
        def to_der
            @ocsp_response.to_der
        end

        # @param ca_cert [OpenSSL::X509::Certificate] the CA certificate to verify against
        # @return [Boolean] true if the response is valid according to the given root
        def verify(ca_cert)
            #TODO: learn what this really means
            #and how to suppress the output when it doesn't match
            #/Users/pkehrer/Code/r509/spec/ocsp_spec.rb:107: warning: error:27069076:OCSP routines:OCSP_basic_verify:signer certificate not found
            store = OpenSSL::X509::Store.new
            store.add_cert(ca_cert)
            @ocsp_response.basic.verify([ca_cert], store)
        end

        # @param ocsp_request [OpenSSL::OCSP::Request] the OCSP request whose nonce to check
        # @return [R509::Ocsp::Request] the status code of the nonce check
        def check_nonce(ocsp_request)
            ocsp_request.check_nonce(@ocsp_response.basic)
        end
    end
end

module R509::Ocsp::Helper
    class RequestChecker
        def initialize(configs, validity_checker)
            @configs = configs
            unless @configs.kind_of?(Array)
                raise R509::R509Error, "Must pass an array of R509::Config objects"
            end
            if @configs.empty?
                raise R509::R509Error, "Must be at least one R509::Config object"
            end
            @validity_checker = validity_checker
            if @validity_checker.nil?
                raise R509::R509Error, "Must supply a R509::Validity::Checker"
            end
            if not @validity_checker.respond_to?(:check)
                raise R509::R509Error, "The validity checker must have a check method"
            end
        end
        # Loads and checks a raw OCSP request
        #
        # @param request [String] DER encoded OCSP request string
        def check_request(request)
            parsed_request = OpenSSL::OCSP::Request.new request
            { :parsed_request => parsed_request,
                :statuses => parsed_request.certid.map { |certid|
                    validated_config = R509::Helper::FirstConfigMatch::match(certid,@configs)
                    check_status(certid, validated_config)
                }
            }
        end

        private

        # Checks the status of a certificate with the corresponding CA
        # @param certid [OpenSSL::OCSP::CertificateId] The certId object from check_request
        # @param validated_config [R509::Config]
        def check_status(certid, validated_config)
            if(validated_config == nil) then
                return nil
            else
                validity_status = @validity_checker.check(certid.serial)
                return {
                    :certid => certid,
                    :status => validity_status.ocsp_status,
                    :revocation_reason => validity_status.revocation_reason,
                    :revocation_time => validity_status.revocation_time,
                    :config => validated_config
                }
            end
        end
    end

    class ResponseSigner
        def initialize(options)
            if options.has_key?(:copy_nonce)
                @copy_nonce = options[:copy_nonce]
            else
                @copy_nonce = false
            end
            @configs = options[:configs]
            unless @configs.kind_of?(Array)
                raise R509::R509Error, "Must pass an array of R509::Config objects"
            end
            if @configs.empty?
                raise R509::R509Error, "Must be at least one R509::Config object"
            end
            @default_config = @configs[0]
        end

        # Signs response. Only call this after loading a request or adding your own status
        #
        # @param request_data [Hash] of { :parsed_request, :statuses }
        # @return [OpenSSL::OCSP::OCSPResponse]
        def sign_response(request_data)
            basic_response = OpenSSL::OCSP::BasicResponse.new

            basic_response.copy_nonce(request_data[:parsed_request]) if @copy_nonce

            has_invalid = false
            config = nil
            request_data[:statuses].each do |status|
                if status.nil? or status[:config].nil?
                    has_invalid = true
                else
                    if config.nil?
                        config = status[:config]
                    end
                    if config != status[:config]
                        has_invalid = true
                    end

                    basic_response.add_status(status[:certid],
                                            status[:status],
                                            status[:revocation_reason],
                    #TODO: WHY IN THE HELL IS REVOCATION TIME RELATIVE TO NOW? THAT CAN'T BE RIGHT!
                                            status[:revocation_time],
                                            -1*status[:config].ocsp_start_skew_seconds,
                                            status[:config].ocsp_validity_hours*3600,
                                            [] #array of OpenSSL::X509::Extensions
                                            )
                end
            end
            if has_invalid
                response_status = OpenSSL::OCSP::RESPONSE_STATUS_UNAUTHORIZED
            else
                response_status = OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
            end
            if config.nil?
                config = @default_config
            end
            basic_response.sign(config.ocsp_cert,config.ocsp_key,config.ocsp_chain)

            #turns out BasicResponse#sign can take up to 4 params
            #cert
            #key
            #array of OpenSSL::X509::Certificates
            #flags (not sure what the enumeration of those are)

            # first arg is the response status code, comes from this list
            # these can also be enumerated via OpenSSL::OCSP::RESPONSE_STATUS_*
            #OCSPResponseStatus ::= ENUMERATED {
            #    successful            (0),      --Response has valid confirmations
            #    malformedRequest      (1),      --Illegal confirmation request
            #    internalError         (2),      --Internal error in issuer
            #    tryLater              (3),      --Try again later
            #                       --(4) is not used
            #    sigRequired           (5),      --Must sign the request
            #    unauthorized          (6)       --Request unauthorized
            #}
            #
            R509::Ocsp::Response.new(OpenSSL::OCSP::Response.create(response_status,basic_response))
        end
    end
end



