# vim: set sts=2 ts=2 sw=2 et:
module OpenSSL::PKey
  class PKey
    def sign_x509_der!(digest, der)
      if !digest.kind_of? OpenSSL::Digest
        raise OpenSSL::PKey::PKeyError, "must provide a Digest"
      end
      if !self.private?
        raise OpenSSL::PKey::PKeyError, "must be a private key"
      end
      if der.kind_of? OpenSSL::ASN1::ASN1Data
        der_out = false
        asn = der
      elsif der.kind_of? String
        der_out = true
        begin
          asn = OpenSSL::ASN1.decode(der)
        rescue OpenSSL::ASN1::ASN1Error => e
          raise OpenSSL::PKey::PKeyError, "invalid DER (#{e.message})"
        end
      else
        raise OpenSSL::PKey::PKeyError, "must provide ASN1Data or DER string"
      end

      # Sanity check the structure; it needs be a SEQUENCE with something to sign
      if !asn.kind_of? OpenSSL::ASN1::Sequence
        raise OpenSSL::PKey::PKeyError, "DER must be a sequence"
      end
      if (!asn.value.kind_of? Array) || (asn.value.length == 0) || (!asn.value[0].kind_of? OpenSSL::ASN1::ASN1Data)
        raise OpenSSL::PKey::PKeyError, "DER must have data to be signed"
      end

      # Sign it
      data = asn.value[0].to_der
      asn.value[1] = OpenSSL::ASN1::Sequence.new(self.class.algorithm_identifier(digest))
      asn.value[2] = OpenSSL::ASN1::BitString.new(self.sign(digest, data))
      if der_out
        return asn.to_der
      else
        return asn
      end 
    end
  end

  class RSA
    def self.algorithm_identifier(hash)
      if !((hash.kind_of? Class) || (hash.kind_of? OpenSSL::Digest))
        raise OpenSSL::PKey::PKeyError, "Unknown digest type"
      end
      if hash == OpenSSL::Digest::SHA512 || (hash.kind_of? OpenSSL::Digest::SHA512)
        return [OpenSSL::ASN1::ObjectId.new("1.2.840.113549.1.1.13"), OpenSSL::ASN1::Null.new(nil)]
      elsif hash == OpenSSL::Digest::SHA384 || (hash.kind_of? OpenSSL::Digest::SHA384)
        return [OpenSSL::ASN1::ObjectId.new("1.2.840.113549.1.1.12"), OpenSSL::ASN1::Null.new(nil)]
      elsif hash == OpenSSL::Digest::SHA256 || (hash.kind_of? OpenSSL::Digest::SHA256)
        return [OpenSSL::ASN1::ObjectId.new("1.2.840.113549.1.1.11"), OpenSSL::ASN1::Null.new(nil)]
      elsif hash == OpenSSL::Digest::SHA1 || (hash.kind_of? OpenSSL::Digest::SHA1)
        return [OpenSSL::ASN1::ObjectId.new("1.2.840.113549.1.1.5"), OpenSSL::ASN1::Null.new(nil)]
      elsif hash == OpenSSL::Digest::MD5 || (hash.kind_of? OpenSSL::Digest::MD5)
        return [OpenSSL::ASN1::ObjectId.new("1.2.840.113549.1.1.4"), OpenSSL::ASN1::Null.new(nil)]
      elsif hash == OpenSSL::Digest::MD4 || (hash.kind_of? OpenSSL::Digest::MD4)
        return [OpenSSL::ASN1::ObjectId.new("1.2.840.113549.1.1.3"), OpenSSL::ASN1::Null.new(nil)]
      elsif hash == OpenSSL::Digest::MD2 || (hash.kind_of? OpenSSL::Digest::MD2)
        return [OpenSSL::ASN1::ObjectId.new("1.2.840.113549.1.1.2"), OpenSSL::ASN1::Null.new(nil)]
      end
      raise OpenSSL::PKey::PKeyError, "Unsupported digest algorithm"
    end
  end

  class DSA
    def self.algorithm_identifier(hash)
      if !((hash.kind_of? Class) || (hash.kind_of? OpenSSL::Digest))
        raise OpenSSL::PKey::PKeyError, "Unknown digest type"
      end
      if hash == OpenSSL::Digest::SHA256 || (hash.kind_of? OpenSSL::Digest::SHA256)
        return [OpenSSL::ASN1::ObjectId.new("2.16.840.1.101.3.4.3.2")]
      elsif hash == OpenSSL::Digest::SHA1 || (hash.kind_of? OpenSSL::Digest::SHA1)
        return [OpenSSL::ASN1::ObjectId.new("1.2.840.10040.4.3")]
      end
      raise OpenSSL::PKey::PKeyError, "Unsupported digest algorithm"
    end
  end

  class EC
    def self.algorithm_identifier(hash)
      if !((hash.kind_of? Class) || (hash.kind_of? OpenSSL::Digest))
        raise OpenSSL::PKey::PKeyError, "Unknown digest type"
      end
      if hash == OpenSSL::Digest::SHA512 || (hash.kind_of? OpenSSL::Digest::SHA512)
        return [OpenSSL::ASN1::ObjectId.new("1.2.840.10040.4.3.4")]
      elsif hash == OpenSSL::Digest::SHA384 || (hash.kind_of? OpenSSL::Digest::SHA384)
        return [OpenSSL::ASN1::ObjectId.new("1.2.840.10045.4.3.3")]
      elsif hash == OpenSSL::Digest::SHA256 || (hash.kind_of? OpenSSL::Digest::SHA256)
        return [OpenSSL::ASN1::ObjectId.new("1.2.840.10045.4.3.2")]
      elsif hash == OpenSSL::Digest::SHA1 || (hash.kind_of? OpenSSL::Digest::SHA1)
        return [OpenSSL::ASN1::ObjectId.new("1.2.840.10045.4.1")]
      end
      raise OpenSSL::PKey::PKeyError, "Unsupported digest algorithm"
    end
  end
end 
