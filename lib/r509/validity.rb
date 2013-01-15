require 'openssl'

#Module for holding classes for writing and reading certificate validity information (used for serving OCSP responses)
module R509::Validity
  #mapping from OpenSSL
  VALID = OpenSSL::OCSP::V_CERTSTATUS_GOOD
  REVOKED = OpenSSL::OCSP::V_CERTSTATUS_REVOKED
  UNKNOWN = OpenSSL::OCSP::V_CERTSTATUS_UNKNOWN

  #data about the status of a certificate
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

    # @return [OpenSSL::OCSP::STATUS] OpenSSL status constants when passing R509 constants
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

  #abstract base class for a Writer
  class Writer
    def issue(issuer, serial)
      raise NotImplementedError, "You must call #issue on a subclass of Writer"
    end

    def revoke(issuer, serial, reason)
      raise NotImplementedError, "You must call #revoke on a subclass of Writer"
    end

    # is_available? is meant to be implemented to check if the backend store you choose to implement is currently working.
    # see r509-ocsp-responder and r509-validity-redis for an example of use
    def is_available?
      raise NotImplementedError, "You must call #is_available? on a subclass of Writer"
    end
  end

  #abstract base class for a Checker
  class Checker
    def check(issuer, serial)
      raise NotImplementedError, "You must call #check on a subclass of Checker"
    end

    # is_available? is meant to be implemented to check if the backend store you choose to implement is currently working.
    # see r509-ocsp-responder and r509-validity-redis for an example of use
    def is_available?
      raise NotImplementedError, "You must call #is_available? on a subclass of Checker"
    end
  end

  #default implementaton of the Checker class. Used for tests. DO NOT USE OTHERWISE
  class DefaultChecker < R509::Validity::Checker
    def check(issuer, serial)
      R509::Validity::Status.new(:status => R509::Validity::VALID)
    end

    def is_available?
      true
    end
  end

  #default implementaton of the Writer class. Does nothing (obviously)
  class DefaultWriter < R509::Validity::Writer
    def issue(issuer, serial)
    end

    def revoke(issuer, serial, reason)
    end

    def is_available?
      true
    end
  end
end
