require 'openssl'
require 'r509/Exceptions'
require 'r509/Config'
require 'r509/HelperClasses'

# OCSP related classes (signing, response, request)
module R509::Ocsp
    # A class for signing OCSP responses
    class Signer

        # @option options [Boolean] :copy_nonce copy nonce from request to response?
        # @option options [Array<R509::Config>] :configs array of configs corresponding to all
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


        # @param request [String,OpenSSL::OCSP::Request] OCSP request (string or parsed object)
        # @return [OpenSSL::OCSP::Request] full response object
        def handle_request(request)
            begin
                parsed_request = OpenSSL::OCSP::Request.new request
            rescue
                return @response_signer.create_response(OpenSSL::OCSP::RESPONSE_STATUS_MALFORMEDREQUEST)
            end

            statuses = @request_checker.check_statuses(parsed_request)
            if not @request_checker.validate_statuses(statuses)
                return @response_signer.create_response(OpenSSL::OCSP::RESPONSE_STATUS_UNAUTHORIZED)
            end

            basic_response = @response_signer.create_basic_response(parsed_request,statuses)

            return @response_signer.create_response(
                OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL,
                basic_response
            )
        end

    end
end

#holds OCSP request related items
module R509::Ocsp::Request
    # contains constants r509 uses for OCSP responses
    module Nonce
        #these values are defined at
        #http://www.ruby-doc.org/stdlib-1.9.3/libdoc/openssl/rdoc/OpenSSL/OCSP/Request.html
        PRESENT_AND_EQUAL = 1
        BOTH_ABSENT = 2
        RESPONSE_ONLY = 3
        NOT_EQUAL = 0
        REQUEST_ONLY = -1
    end
end

module R509::Ocsp
    #builds OCSP responses
    class Response
        # @param ocsp_response [OpenSSL::OCSP::Response]
        def initialize(ocsp_response)
            if not ocsp_response.kind_of?(OpenSSL::OCSP::Response)
                raise R509::R509Error, 'You must pass an OpenSSL::OCSP::Response object to the constructor. See R509::Ocsp::Response.parse if you are trying to parse'
            end
            @ocsp_response = ocsp_response
        end
        # @param [String, OpenSSL::OCSP::Response] parses an existing response
        # @return [R509::Ocsp::Response]
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

        # @return [OpenSSL::OCSP::BasicResponse]
        def basic
            @ocsp_response.basic
        end

        # @param ca_cert [OpenSSL::X509::Certificate] the CA certificate to verify against
        # @return [Boolean] true if the response is valid according to the given root
        def verify(ca_cert)
            store = OpenSSL::X509::Store.new
            store.add_cert(ca_cert)
            #suppress verbosity since #verify will output a warning if it does not match
            #as well as returning false. we just want the boolean
            original_verbosity = $VERBOSE
            $VERBOSE = nil
            #still a bit unclear on why we add to store and pass in array to verify
            result = @ocsp_response.basic.verify([ca_cert], store)
            $VERBOSE = original_verbosity
            return result
        end

        # @param ocsp_request [OpenSSL::OCSP::Request] the OCSP request whose nonce to check
        # @return [R509::Ocsp::Request::Nonce::CONSTANT] the status code of the nonce check
        def check_nonce(ocsp_request)
            ocsp_request.check_nonce(@ocsp_response.basic)
        end
    end
end

#Helper module for OCSP handling
module R509::Ocsp::Helper
    # checks requests for validity against a set of configs
    class RequestChecker
        # @param [Array<R509::Config::CaConfig>] configs
        # @param [R509::Validity::Checker] validity_checker an implementation of the R509::Validity::Checker class
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
        # @param request [OpenSSL::OCSP::Request] OpenSSL OCSP Request object
        # @return [Hash] hash from the check_status method
        def check_statuses(request)
            request.certid.map { |certid|
                validated_config = R509::Helper::FirstConfigMatch::match(certid,@configs)
                check_status(certid, validated_config)
            }
        end

        # Determines whether the statuses constitute a request that is compliant.
        # No config means we don't know the CA, different configs means there are
        # requests from two different CAs in there. Both are invalid.
        #
        # @param statuses [Array<Hash>] array of hashes from check_statuses
        # @return [Boolean]
        def validate_statuses(statuses)
            validity = true
            config = nil

            statuses.each do |status|
                if status[:config].nil?
                    validity = false
                end
                if config.nil?
                    config = status[:config]
                end
                if config != status[:config]
                    validity = false
                end
            end

            validity
        end

        private

        # Checks the status of a certificate with the corresponding CA
        # @param certid [OpenSSL::OCSP::CertificateId] The certId object from check_statuses
        # @param validated_config [R509::Config]
        def check_status(certid, validated_config)
            if(validated_config == nil) then
                return {
                    :certid => certid,
                    :config => nil
                }
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

    #signs OCSP responses
    class ResponseSigner
        # @option options [Boolean] :copy_nonce
        # @option options [Array<R509::Config::CaConfig>] :configs
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

        # It is UNWISE to call this method directly because it assumes that the request is
        # validated. You probably want to take a look at R509::Ocsp::Signer#handle_request
        #
        # @param request [OpenSSL::OCSP::Request]
        # @param statuses [Hash] hash from R509::Ocsp::Helper::RequestChecker#check_statuses
        # @return [OpenSSL::OCSP::BasicResponse]
        def create_basic_response(request,statuses)
            basic_response = OpenSSL::OCSP::BasicResponse.new

            basic_response.copy_nonce(request) if @copy_nonce

            statuses.each do |status|
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

            #this method assumes the request data is validated by validate_request so all configs will be the same and
            #we can choose to use the first one safely
            config = statuses[0][:config]

            #confusing, but R509::Cert contains R509::PrivateKey under #key. PrivateKey#key gives the OpenSSL object
            #turns out BasicResponse#sign can take up to 4 params
            #cert, key, array of OpenSSL::X509::Certificates, flags (not sure what the enumeration of those are)
            basic_response.sign(config.ocsp_cert.cert,config.ocsp_cert.key.key,config.ocsp_chain)
        end

        # Builds final response.
        #
        # @param response_status [OpenSSL::OCSP::RESPONSE_STATUS_*] the primary response status
        # @param basic_response [OpenSSL::OCSP::BasicResponse] an optional basic response object
        # generated by create_basic_response
        # @return [OpenSSL::OCSP::OCSPResponse]
        def create_response(response_status,basic_response=nil)

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
            R509::Ocsp::Response.new(
                OpenSSL::OCSP::Response.create(
                    response_status, basic_response
                )
            )
        end
    end
end



