module R509
  # Various helper methods to reduce duplication across classes. These methods
  # are used in the Cert, CSR, SPKI, and PrivateKey classes.
  module Helpers

    # Returns whether the public key is RSA
    #
    # @return [Boolean] true if the public key is RSA, false otherwise
    def rsa?
      internal_obj.public_key.kind_of?(OpenSSL::PKey::RSA)
    end

    # Returns whether the public key is DSA
    #
    # @return [Boolean] true if the public key is DSA, false otherwise
    def dsa?
      internal_obj.public_key.kind_of?(OpenSSL::PKey::DSA)
    end

    # Returns whether the public key is EC
    #
    # @return [Boolean] true if the public key is EC, false otherwise
    def ec?
      internal_obj.public_key.kind_of?(OpenSSL::PKey::EC)
    end

    # Returns key algorithm (RSA/DSA/EC)
    #
    # @return [String] value of the key algorithm.
    def key_algorithm
      if self.rsa?
        "RSA"
      elsif self.dsa?
        "DSA"
      elsif self.ec?
        "EC"
      end
    end

    # Returns the short name of the elliptic curve used to generate the public key
    # if the key is EC. If not, raises an error.
    #
    # @return [String] elliptic curve name
    def curve_name
      if self.ec?
        internal_obj.public_key.group.curve_name
      else
        raise R509::R509Error, 'Curve name is only available with EC'
      end
    end

    # Returns the bit strength of the key used to create the SPKI
    # @return [Integer] the integer bit strength.
    def bit_strength
      if self.rsa?
        return internal_obj.public_key.n.num_bits
      elsif self.dsa?
        return internal_obj.public_key.p.num_bits
      elsif self.ec?
        raise R509::R509Error, 'Bit strength is not available for EC at this time.'
      end
    end

    # Writes the object into PEM format
    # @param [String, #write] filename_or_io Either a string of the path for
    #  the file that you'd like to write, or an IO-like object.
    def write_pem(filename_or_io)
      write_data(filename_or_io, internal_obj.to_pem)
    end

    # Writes the object into DER format
    # @param [String, #write] filename_or_io Either a string of the path for
    #  the file that you'd like to write, or an IO-like object.
    def write_der(filename_or_io)
      write_data(filename_or_io, internal_obj.to_der)
    end

    # Converts the object into PEM format
    #
    # @return [String] the object converted into PEM format.
    def to_pem
        internal_obj.to_pem
    end

    # Converts the object into DER format
    #
    # @return [String] the object converted into DER format.
    def to_der
        internal_obj.to_der
    end

    # @private
    def load_private_key(opts)
      if opts.has_key?(:key)
        if opts[:key].kind_of?(R509::PrivateKey)
          return opts[:key]
        else
          return R509::PrivateKey.new(:key => opts[:key])
        end
      end
    end

    # @private
    def internal_obj
      raise R509::R509Error, "Internal object for helpers not implemented"
    end

  end
end
