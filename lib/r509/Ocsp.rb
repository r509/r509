require 'openssl'
require 'r509/Exceptions'
require 'r509/Config'
require 'r509/HelperClasses'
require 'r509/CertificateStatusChecker'

module R509::Ocsp
    # A class for signing OCSP responses
    class Signer

        # @param config [Array<R509::Config>] array of configs corresponding to all
        # possible OCSP issuance roots
        # that we want to issue OCSP responses for
        def initialize(configs)
            @request_checker = Helper::RequestChecker.new(configs)
            @response_signer = Helper::ResponseSigner.new(configs)
        end

        def check_request(request)
            @request_checker.check_request(request)
        end

        def sign_response(statuses)
            @response_signer.sign_response(statuses)
        end
    end
end

module R509::Ocsp::Helper
    class RequestChecker
        def initialize(configs)
            @configs = configs
            unless @configs.kind_of?(Array)
                raise R509::R509Error, "Must pass an array of R509::Config objects"
            end
            if @configs.empty?
                raise R509::R509Error, "Must be at least one R509::Config object"
            end
        end
        # Loads and checks a raw OCSP request
        #
        # @param request [String] DER encoded OCSP request string
        def check_request(request)
            parsed_request = OpenSSL::OCSP::Request.new request
            parsed_request.certid.map do |certid|
                validated_config = R509::Helper::FirstConfigMatch::match(certid,@configs)
                check_status(certid,validated_config)
            end
        end

        private

        # Checks the status of a certificate with the corresponding CA
        # @param certid [OpenSSL::OCSP::CertificateId] The certId object from check_request
        # @param validated_config [R509::Config]
        def check_status(certid,validated_config)
            if(validated_config == nil) then
                return nil
            else
                certificate_checker = CertificateStatusChecker.new(validated_config)
                certificate_checker.get_status(certid)
            end
        end
    end

    class ResponseSigner
        def initialize(configs)
            @configs = configs
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
        # @return [OpenSSL::OCSP::OCSPResponse]
        def sign_response(statuses)
            basic_response = OpenSSL::OCSP::BasicResponse.new

            has_invalid = false
            config = nil
            statuses.each do |status|
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
            OpenSSL::OCSP::Response.create(response_status,basic_response)
        end
    end
end



