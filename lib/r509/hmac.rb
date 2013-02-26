require 'openssl'
require 'r509/message_digest'
require 'r509/exceptions'

module R509
  # A helper class to make generating HMAC signatures easier. This primarily focuses
  # on preventing common mistakes like keys that are too short or have too little
  # entropy (e.g., English phrases)
  class HMAC
    # @option opts [String] :message_digest (sha512) The message digest to use
    # @option opts [String] :key String key. This must be the same byte length as the hash output (per RFC2104 recommendation, see below). You can generate a key with R509::HMAC.generate_key(message_digest)
    # @option opts [String] :data Data to sign
    # @option opts [Boolean] :allow_low_entropy (False) A method to optionally override the Shannon entropy checks as well as the minimum key length. These checks exist to try to catch extremely bad keys, so disabling them is not recommended.
    # @return [String] hexadecimal digest
    def self.hexdigest(opts)
      md = self.validate(opts)

      OpenSSL::HMAC.hexdigest(md.digest,opts[:key],opts[:data])
    end

    # @option opts [String] :message_digest (sha512) The message digest to use
    # @option opts [String] :key String key. This must be the same byte length as the hash output (per RFC2104 recommendation, see below). You can generate a key with R509::HMAC.generate_key(message_digest)
    # @option opts [String] :data Data to sign
    # @option opts [Boolean] :allow_low_entropy (False) A method to optionally override the Shannon entropy checks as well as the minimum key length. These checks exist to try to catch extremely bad keys, so disabling them is not recommended.
    # @return [String] binary digest
    def self.digest(opts)
      md = self.validate(opts)

      OpenSSL::HMAC.digest(md.digest,opts[:key],opts[:data])
    end

    # Generating proper keys for HMAC is a bit tricky, so let's quote RFC 2104
    #
    # The definition of HMAC requires a cryptographic hash function, which
    # we denote by H, and a secret key K. We assume H to be a cryptographic
    # hash function where data is hashed by iterating a basic compression
    # function on blocks of data.   We denote by B the byte-length of such
    # blocks (B=64 for all the above mentioned examples of hash functions),
    # and by L the byte-length of hash outputs (L=16 for MD5, L=20 for
    # SHA-1).  The authentication key K can be of any length up to B, the
    # block length of the hash function.  Applications that use keys longer
    # than B bytes will first hash the key using H and then use the
    # resultant L byte string as the actual key to HMAC. In any case the
    # minimal recommended length for K is L bytes (as the hash output
    # length). (...)
    #
    # The key for HMAC can be of any length (keys longer than B bytes are
    # first hashed using H).  However, less than L bytes is strongly
    # discouraged as it would decrease the security strength of the
    # function.  Keys longer than L bytes are acceptable but the extra
    # length would not significantly increase the function strength. (A
    # longer key may be advisable if the randomness of the key is
    # considered weak.)
    #
    # Keys need to be chosen at random (or using a cryptographically strong
    # pseudo-random generator seeded with a random seed), and periodically
    # refreshed.  (Current attacks do not indicate a specific recommended
    # frequency for key changes as these attacks are practically
    # infeasible.  However, periodic key refreshment is a fundamental
    # security practice that helps against potential weaknesses of the
    # function and keys, and limits the damage of an exposed key.)
    #
    # Okay, that was pretty involved, but here are the rules we're going to
    # use for this module:
    #
    # * All keys *must* be >= L bytes long. For each message digest algorithm we will determine the digest length in bytes and require the key to be at least that long.
    # * It is *strongly* *recommended* that you use a decent method of creating your HMAC key. Like, say, this method.
    #
    # @param [String] message_digest The message digest you intend to use for HMAC. sha1, sha224, sha256, sha384, sha512, md5 allowed
    # @return [String] Pseudorandom key whose length matches the provided digest output length in bytes
    def self.generate_key(message_digest='sha512')
      md = R509::MessageDigest.new(message_digest)
      OpenSSL::Random.random_bytes(md.digest.digest_length)
    end

    private
    def self.validate(opts)
      if not opts.kind_of?(Hash)
        raise ArgumentError, 'Must provide a hash of options'
      end
      default_opts = { :message_digest => 'sha512', :allow_low_entropy => false }
      opts = default_opts.merge(opts)

      if not opts.has_key?(:key) or opts[:key].empty?
        raise ArgumentError, ":key is required"
      end
      if not opts.has_key?(:data) or opts[:data].empty?
        raise ArgumentError, ":data is required"
      end

      md = R509::MessageDigest.new(opts[:message_digest])
      required_length = md.digest.digest_length
      if required_length > opts[:key].bytesize and not opts[:allow_low_entropy] == true
        raise R509::R509Error, "Key must be at least equal to the digest length. Since your digest is #{md.name} the length must be #{required_length} bytes. This check can be overridden with :allow_low_entropy if needed"
      end

      # 3.5 is semi-arbitrary but based on the empirically calculated average entropy
      # found when calling the method on OpenSSL::Random.random_bytes as well as on
      # English strings (which are the most common lousy keys). This is a relatively
      # lax value.
      if not opts[:allow_low_entropy] == true and self.shannon_entropy(opts[:key]) < 3.5
        raise R509::R509Error, "The shannon entropy of this key is low and therefore is not considered secure. Consider using a key from the R509::HMAC.generate_key method. This check can be overridden with :allow_low_entropy if needed"
      end
      md
    end

    # calculates the shannon entropy of a string
    # http://en.wikipedia.org/wiki/Entropy_(information_theory)
    # http://www.shannonentropy.netmark.pl/calculate/
    def self.shannon_entropy(key)
      total = key.bytesize

      frequency = Hash.new { 0 }
      key.each_byte do |b|
        frequency[b] += 1
      end

      entropy = 0
      frequency.each do |k,v|
        f = v.to_f/total
        entropy += f * Math.log2(f)
      end
      entropy * -1.0
    end
  end
end
