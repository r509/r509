require 'openssl'

module R509::Validity
    VALID = OpenSSL::OCSP::V_CERTSTATUS_GOOD
    REVOKED = OpenSSL::OCSP::V_CERTSTATUS_REVOKED
    UNKNOWN = OpenSSL::OCSP::V_CERTSTATUS_UNKNOWN

    class Status
        attr_reader :status, :revocation_time, :revocation_reason

        def initialize(options)
            @status = options[:status]
            @revocation_time = options[:revocation_time] || nil
            @revocation_reason = options[:revocation_reason] || 0
        end

        def ocsp_status
            case @status
            when R509::Validity::VALID
                OpenSSL::OCSP::V_CERTSTATUS_GOOD
            when R509::Validity::REVOKED
                OpenSSL::OCSP::V_CERTSTATUS_REVOKED
            when R509::Validity::UNKNOWN
                OpenSSL::OCSP::V_CERTSTATUS_UNKNOWN
            else
                OpenSSL::OCSP::V_CERTSTATUS_UNKNOWN
            end
        end
    end

    class Writer
    end

    class Checker
    end

    class DefaultChecker < R509::Validity::Checker
        def check(serial)
            R509::Validity::Status.new(:status => R509::Validity::VALID)
        end
    end

    class DefaultWriter < R509::Validity::Writer
        def write(serial, status)
        end
    end
end
