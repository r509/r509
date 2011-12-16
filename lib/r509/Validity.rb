require 'openssl'

module R509::Validity
    VALID = OpenSSL::OCSP::V_CERTSTATUS_GOOD
    REVOKED = OpenSSL::OCSP::V_CERTSTATUS_REVOKED
    UNKNOWN = OpenSSL::OCSP::V_CERTSTATUS_UNKNOWN

    class Status
        attr_reader :status, :revocation_time, :revocation_reason

        def initialize(options={})
            @status = options[:status]
            @revocation_time = options[:revocation_time] || nil
            @revocation_reason = options[:revocation_reason] || 0

            if (@status == R509::Validity::REVOKED and @revocation_time.nil?)
                @revocation_time = Time.now.to_i
            end
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
        def issue(serial)
            raise NotImplementedError, "You must call #issue on a subclass of Writer"
        end

        def revoke(serial, reason)
            raise NotImplementedError, "You must call #revoke on a subclass of Writer"
        end
    end

    class Checker
        def check(serial)
            raise NotImplementedError, "You must call #check on a subclass of Checker"
        end
    end

    class DefaultChecker < R509::Validity::Checker
        def check(serial)
            R509::Validity::Status.new(:status => R509::Validity::VALID)
        end
    end

    class DefaultWriter < R509::Validity::Writer
        def issue(serial)
        end

        def revoke(serial, reason)
        end
    end
end
