require 'openssl'
require 'r509/asn1'
require 'set'

module R509
  class Cert
    # module to contain extension classes for R509::Cert
    module Extensions

      private
      R509_EXTENSION_CLASSES = Set.new

      # Registers a class as being an R509 certificate extension class. Registered
      # classes are used by #wrap_openssl_extensions to wrap OpenSSL extensions
      # in R509 extensions, based on the OID.
      def self.register_class( r509_ext_class )
        raise ArgumentError.new("R509 certificate extensions must have an OID") if r509_ext_class::OID.nil?
        R509_EXTENSION_CLASSES << r509_ext_class
      end


      public
      # Implements the BasicConstraints certificate extension, with methods to
      # provide access to the components and meaning of the extension's contents.
      class BasicConstraints < OpenSSL::X509::Extension
        # friendly name for BasicConstraints OID
        OID = "basicConstraints"
        Extensions.register_class(self)

        attr_reader :path_length

        # See OpenSSL::X509::Extension#initialize
        def initialize(arg)
          if arg.kind_of?(Hash)
            ef = OpenSSL::X509::ExtensionFactory.new
            if arg[:ca] == true
              bc_value = "CA:TRUE"
              if not arg[:path_length].nil?
                bc_value += ",pathlen:#{arg[:path_length]}"
              end
            else
              bc_value = "CA:FALSE"
            end
            arg = ef.create_extension("basicConstraints", bc_value, true)
          end

          super(arg)

          data = R509::ASN1.get_extension_payload(self)
          @is_ca = false
          #   BasicConstraints ::= SEQUENCE {
          #        cA                      BOOLEAN DEFAULT FALSE,
          #        pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
          data.entries.each do |entry|
            if entry.kind_of?(OpenSSL::ASN1::Boolean)
              @is_ca = entry.value
            else
              # There are only two kinds of entries permitted so anything
              # else is an integer pathlength. it is in OpenSSL::BN form by default
              # but that's annoying so let's cast it.
              @path_length = entry.value.to_i
            end
          end
        end

        def is_ca?()
          return @is_ca == true
        end

        # Returns true if the path length allows this certificate to be used to
        # create subordinate signing certificates beneath it. Does not check if
        # there is a pathlen restriction in the cert chain above the current cert
        def allows_sub_ca?()
          return false if @path_length.nil?
          return @path_length > 0
        end
      end

      # Implements the KeyUsage certificate extension, with methods to
      # provide access to the components and meaning of the extension's contents.
      class KeyUsage < OpenSSL::X509::Extension
        # friendly name for KeyUsage OID
        OID = "keyUsage"
        Extensions.register_class(self)

        # An array of the key uses allowed.
        attr_reader :allowed_uses

        # OpenSSL short name for Digital Signature
        AU_DIGITAL_SIGNATURE = "digitalSignature"
        # OpenSSL short name for Non Repudiation (also known as content commitment)
        AU_NON_REPUDIATION = "nonRepudiation"
        # OpenSSL short name for Key Encipherment
        AU_KEY_ENCIPHERMENT = "keyEncipherment"
        # OpenSSL short name for Data Encipherment
        AU_DATA_ENCIPHERMENT = "dataEncipherment"
        # OpenSSL short name for Key Agreement
        AU_KEY_AGREEMENT = "keyAgreement"
        # OpenSSL short name for Certificate Sign
        AU_KEY_CERT_SIGN = "keyCertSign"
        # OpenSSL short name for CRL Sign
        AU_CRL_SIGN = "cRLSign"
        # OpenSSL short name for Encipher Only
        AU_ENCIPHER_ONLY = "encipherOnly"
        # OpenSSL short name for Decipher Only
        AU_DECIPHER_ONLY = "decipherOnly"

        # See OpenSSL::X509::Extension#initialize
        def initialize(arg)
          if arg.kind_of?(Array)
            ef = OpenSSL::X509::ExtensionFactory.new
            arg = ef.create_extension("keyUsage", arg.join(","),false)
          end

          super(arg)

          data = R509::ASN1.get_extension_payload(self)

          # There are 9 possible bits, which means we need 2 bytes
          # to represent them all. When the last bit is not set
          # the second byte is not encoded. let's add it back so we can
          # have the full bitmask for comparison
          if data.size == 1
            data = data + "\0"
          end
          bit_mask = data.unpack('n')[0] # treat it as a 16-bit unsigned big endian
          #      KeyUsage ::= BIT STRING {
          #           digitalSignature        (0),
          #           nonRepudiation          (1), -- recent editions of X.509 have
          #                                -- renamed this bit to contentCommitment
          #           keyEncipherment         (2),
          #           dataEncipherment        (3),
          #           keyAgreement            (4),
          #           keyCertSign             (5),
          #           cRLSign                 (6),
          #           encipherOnly            (7),
          #           decipherOnly            (8) }
          @allowed_uses = []
          if bit_mask & 0b1000000000000000 > 0
            @digital_signature = true
            @allowed_uses << AU_DIGITAL_SIGNATURE
          end
          if bit_mask & 0b0100000000000000 > 0
            @non_repudiation = true
            @allowed_uses << AU_NON_REPUDIATION
          end
          if bit_mask & 0b0010000000000000 > 0
            @key_encipherment = true
            @allowed_uses << AU_KEY_ENCIPHERMENT
          end
          if bit_mask & 0b0001000000000000 > 0
            @data_encipherment = true
            @allowed_uses << AU_DATA_ENCIPHERMENT
          end
          if bit_mask & 0b0000100000000000 > 0
            @key_agreement = true
            @allowed_uses << AU_KEY_AGREEMENT
          end
          if bit_mask & 0b0000010000000000 > 0
            @key_cert_sign = true
            @allowed_uses << AU_KEY_CERT_SIGN
          end
          if bit_mask & 0b0000001000000000 > 0
            @crl_sign = true
            @allowed_uses << AU_CRL_SIGN
          end
          if bit_mask & 0b0000000100000000 > 0
            @encipher_only = true
            @allowed_uses << AU_ENCIPHER_ONLY
          end
          if bit_mask & 0b0000000010000000 > 0
            @decipher_only = true
            @allowed_uses << AU_DECIPHER_ONLY
          end
        end

        # Returns true if the given use is allowed by this extension.
        # @param [String] friendly_use_name key usage short name (e.g. digitalSignature, cRLSign, etc)
        #   or one of the AU_* constants in this class
        # @return [Boolean]
        def allows?( friendly_use_name )
          @allowed_uses.include?( friendly_use_name )
        end

        def digital_signature?
          (@digital_signature == true)
        end

        def non_repudiation?
          (@non_repudiation == true)
        end

        def key_encipherment?
          (@key_encipherment == true)
        end

        def data_encipherment?
          (@data_encipherment == true)
        end

        def key_agreement?
          (@key_agreement == true)
        end

        def key_cert_sign?
          (@key_cert_sign == true)
        end

        def crl_sign?
          (@crl_sign == true)
        end

        def encipher_only?
          (@encipher_only == true)
        end

        def decipher_only?
          (@decipher_only == true)
        end
      end

      # Implements the ExtendedKeyUsage certificate extension, with methods to
      # provide access to the components and meaning of the extension's contents.
      class ExtendedKeyUsage < OpenSSL::X509::Extension
        # friendly name for EKU OID
        OID = "extendedKeyUsage"
        Extensions.register_class(self)

        # The OpenSSL short name for TLS Web Server Authentication
        AU_WEB_SERVER_AUTH = "serverAuth"
        # The OpenSSL short name for TLS Web Client Authentication
        AU_WEB_CLIENT_AUTH = "clientAuth"
        # The OpenSSL short name for Code Signing
        AU_CODE_SIGNING = "codeSigning"
        # The OpenSSL short name for E-mail Protection
        AU_EMAIL_PROTECTION = "emailProtection"
        # The OpenSSL short name for OCSP Signing
        AU_OCSP_SIGNING = "OCSPSigning"
        # The OpenSSL short name for Time Stamping
        AU_TIME_STAMPING = "timeStamping"
        # The OpenSSL short name for Any Extended Key Usage
        AU_ANY_EXTENDED_KEY_USAGE = "anyExtendedKeyUsage"

        attr_reader :allowed_uses

        # See OpenSSL::X509::Extension#initialize
        def initialize(arg)
          if arg.kind_of?(Array)
            ef = OpenSSL::X509::ExtensionFactory.new
            arg = ef.create_extension("extendedKeyUsage", arg.join(","),false)
          end

          super(arg)

          @allowed_uses = []
          data = R509::ASN1.get_extension_payload(self)

          data.entries.each do |eku|
            #   The following key usage purposes are defined:
            #
            #   anyExtendedKeyUsage OBJECT IDENTIFIER ::= { id-ce-extKeyUsage 0 }
            #
            #   id-kp OBJECT IDENTIFIER ::= { id-pkix 3 }
            #   id-kp-serverAuth             OBJECT IDENTIFIER ::= { id-kp 1 }
            #   -- TLS WWW server authentication
            #   -- Key usage bits that may be consistent: digitalSignature,
            #   -- keyEncipherment or keyAgreement
            #
            #   id-kp-clientAuth             OBJECT IDENTIFIER ::= { id-kp 2 }
            #   -- TLS WWW client authentication
            #   -- Key usage bits that may be consistent: digitalSignature
            #   -- and/or keyAgreement
            #
            #   id-kp-codeSigning             OBJECT IDENTIFIER ::= { id-kp 3 }
            #   -- Signing of downloadable executable code
            #   -- Key usage bits that may be consistent: digitalSignature
            #
            #   id-kp-emailProtection         OBJECT IDENTIFIER ::= { id-kp 4 }
            #   -- Email protection
            #   -- Key usage bits that may be consistent: digitalSignature,
            #   -- nonRepudiation, and/or (keyEncipherment or keyAgreement)
            #
            #   id-kp-timeStamping            OBJECT IDENTIFIER ::= { id-kp 8 }
            #   -- Binding the hash of an object to a time
            #   -- Key usage bits that may be consistent: digitalSignature
            #   -- and/or nonRepudiation
            #
            #   id-kp-OCSPSigning            OBJECT IDENTIFIER ::= { id-kp 9 }
            #   -- Signing OCSP responses
            #   -- Key usage bits that may be consistent: digitalSignature
            #   -- and/or nonRepudiation

            case eku.value
            when AU_WEB_SERVER_AUTH
              @web_server_authentication = true
            when AU_WEB_CLIENT_AUTH
              @web_client_authentication = true
            when AU_CODE_SIGNING
              @code_signing = true
            when AU_EMAIL_PROTECTION
              @email_protection = true
            when AU_OCSP_SIGNING
              @ocsp_signing = true
            when AU_TIME_STAMPING
              @time_stamping = true
            when AU_ANY_EXTENDED_KEY_USAGE
              @any_extended_key_usage = true
            end
            @allowed_uses << eku.value
          end
        end

        # Returns true if the given use is allowed by this extension.
        # @param [string] friendly_use_name One of the AU_* constants in this class.
        def allows?( friendly_use_name )
          @allowed_uses.include?( friendly_use_name )
        end

        def web_server_authentication?
          (@web_server_authentication == true)
        end

        def web_client_authentication?
          (@web_client_authentication == true)
        end

        def code_signing?
          (@code_signing == true)
        end

        def email_protection?
          (@email_protection == true)
        end

        def ocsp_signing?
          (@ocsp_signing == true)
        end

        def time_stamping?
          (@time_stamping == true)
        end

        def any_extended_key_usage?
          (@any_extended_key_usage == true)
        end
      end

      # Implements the SubjectKeyIdentifier certificate extension, with methods to
      # provide access to the components and meaning of the extension's contents.
      class SubjectKeyIdentifier < OpenSSL::X509::Extension
        # friendly name for Subject Key Identifier OID
        OID = "subjectKeyIdentifier"
        Extensions.register_class(self)

        # takes an existing object, DER-encoded string, or hash with :public_key
        #   in OpenSSL::PKey format. You can get this format from various #public_key methods
        def initialize(arg)
          if arg.kind_of?(Hash)
            ef = OpenSSL::X509::ExtensionFactory.new
            cert = OpenSSL::X509::Certificate.new
            cert.public_key = arg[:public_key]
            ef.subject_certificate = cert
            arg = ef.create_extension("subjectKeyIdentifier", "hash")
          end
          super(arg)
        end

        # @return value of key
        def key
          return self.value
        end
      end

      # Implements the AuthorityKeyIdentifier certificate extension, with methods to
      # provide access to the components and meaning of the extension's contents.
      class AuthorityKeyIdentifier < OpenSSL::X509::Extension
        # friendly name for Authority Key Identifier OID
        OID = "authorityKeyIdentifier"
        Extensions.register_class(self)

        # key_identifier, if present, will be a hex string delimited by colons
        # authority_cert_issuer, if present, will be a GeneralName object
        # authority_cert_serial_number, if present, will be a hex string delimited by colons
        attr_reader :key_identifier, :authority_cert_issuer, :authority_cert_serial_number

        # takes an existing object, DER-encoded string, or hash with :value and :issuer_certificate
        #  :issuer_certificate must be R509::Cert. For the rules of :value see: http://www.openssl.org/docs/apps/x509v3_config.html#Authority_Key_Identifier_. Defaults to keyid
        def initialize(arg)
          if arg.kind_of?(Hash)
            ef = OpenSSL::X509::ExtensionFactory.new
            ef.issuer_certificate = arg[:issuer_certificate].cert
            arg = ef.create_extension("authorityKeyIdentifier", arg[:value] || "keyid") # this could also be keyid:always,issuer:always
          end

          super(arg)

          data = R509::ASN1.get_extension_payload(self)
          #   AuthorityKeyIdentifier ::= SEQUENCE {
          #      keyIdentifier             [0] KeyIdentifier           OPTIONAL,
          #      authorityCertIssuer       [1] GeneralNames            OPTIONAL,
          #      authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
          data.entries.each do |el|
            case el.tag
            when 0
              @key_identifier = el.value.unpack("H*")[0].upcase.scan(/../).join(":")
            when 1
              @authority_cert_issuer = R509::ASN1::GeneralName.new(el.value.first)
            when 2
              arr = el.value.unpack("H*")[0].upcase.scan(/../)
              # OpenSSL's convention is to drop leading 00s, so let's strip that off if
              # present
              if arr[0] == "00"
                arr.delete_at(0)
              end
              @authority_cert_serial_number = arr.join(":")
            end
          end

        end

      end

      # Implements the SubjectAlternativeName certificate extension, with methods to
      # provide access to the components and meaning of the extension's contents.
      class SubjectAlternativeName < OpenSSL::X509::Extension
        # friendly name for SAN OID
        OID = "subjectAltName"
        Extensions.register_class(self)

        attr_reader :general_names

        # takes an existing object, DER-encoded string, array, or R509::ASN1::GeneralNames object.
        #  If you supply an Array it will be parsed by R509::ASN1.general_name_parser to
        #  determine the type of each element. If you prefer to specify it yourself you
        #  can pass a pre-existing GeneralNames object.
        def initialize(arg)
          if arg.kind_of?(Array) or arg.kind_of?(R509::ASN1::GeneralNames)
            serialize = parse_san_names(arg).serialize_names
            ef = OpenSSL::X509::ExtensionFactory.new
            ef.config = OpenSSL::Config.parse(serialize[:conf])
            arg = ef.create_extension("subjectAltName", serialize[:extension_string])
          end
          super(arg)

          data = R509::ASN1.get_extension_payload(self)
          @general_names = R509::ASN1::GeneralNames.new
          data.entries.each do |gn|
            @general_names.add_item(gn)
          end
        end

        # @return [Array<String>] DNS names
        def dns_names
          @general_names.dns_names
        end

        # @return [Array<String>] IP addresses formatted as dotted quad
        def ip_addresses
          @general_names.ip_addresses
        end

        # @return [Array<String>] email addresses
        def rfc_822_names
          @general_names.rfc_822_names
        end

        # @return [Array<String>] URIs (not typically found in SAN extensions)
        def uris
          @general_names.uris
        end

        # @return [Array<R509::Subject>] directory names
        def directory_names
          @general_names.directory_names
        end

        # @return [Array] array of GeneralName objects preserving order found in the extension
        def names
          @general_names.names
        end

        private


        # @private
        def parse_san_names(sans)
          case sans
          when R509::ASN1::GeneralNames then sans
          when Array then R509::ASN1.general_name_parser(sans)
          end
        end
      end

      # Implements the AuthorityInfoAccess certificate extension, with methods to
      # provide access to the components and meaning of the extension's contents.
      class AuthorityInfoAccess < OpenSSL::X509::Extension
        # friendly name for AIA OID
        OID = "authorityInfoAccess"
        Extensions.register_class(self)

        # An array of the OCSP data, if any
        attr_reader :ocsp
        # An array of the CA issuers data, if any
        attr_reader :ca_issuers

        # takes an existing object, DER-encoded string, or Hash. When supplying a hash
        #  it must have an :ocsp_location and/or :ca_issuers_location. Each of these must be
        #  an array of strings.
        def initialize(arg)
          if arg.kind_of?(Hash)
            aia = []
            aia_conf = []

            if not arg[:ocsp_location].nil? and not arg[:ocsp_location].empty?
              gns = R509::ASN1.general_name_parser(arg[:ocsp_location])
              gns.names.each do |ocsp|
                serialize = ocsp.serialize_name
                aia.push "OCSP;#{serialize[:extension_string]}"
                aia_conf.push serialize[:conf]
              end
            end

            if not arg[:ca_issuers_location].nil? and not arg[:ca_issuers_location].empty?
              gns = R509::ASN1.general_name_parser(arg[:ca_issuers_location])
              gns.names.each do |ca_issuers|
                serialize = ca_issuers.serialize_name
                aia.push "caIssuers;#{serialize[:extension_string]}"
                aia_conf.push serialize[:conf]
              end
            end

            if not aia.empty?
              ef = OpenSSL::X509::ExtensionFactory.new
              ef.config = OpenSSL::Config.parse(aia_conf.join("\n"))
              arg = ef.create_extension("authorityInfoAccess",aia.join(","))
            end
          end
          super(arg)

          data = R509::ASN1.get_extension_payload(self)
          @ocsp= R509::ASN1::GeneralNames.new
          @ca_issuers= R509::ASN1::GeneralNames.new
          data.entries.each do |access_description|
            #   AccessDescription  ::=  SEQUENCE {
            #           accessMethod          OBJECT IDENTIFIER,
            #           accessLocation        GeneralName  }
            case access_description.entries[0].value
            when "OCSP"
              @ocsp.add_item(access_description.entries[1])
            when "caIssuers"
              @ca_issuers.add_item(access_description.entries[1])
            end
          end
        end
      end

      # Implements the CRLDistributionPoints certificate extension, with methods to
      # provide access to the components and meaning of the extension's contents.
      class CRLDistributionPoints < OpenSSL::X509::Extension
        # friendly name for CDP OID
        OID = "crlDistributionPoints"
        Extensions.register_class(self)

        # An array of the CRL URIs, if any
        attr_reader :crl

        # See OpenSSL::X509::Extension#initialize
        def initialize(arg)
          if arg.kind_of?(Array)
            serialize = R509::ASN1.general_name_parser(arg).serialize_names
            ef = OpenSSL::X509::ExtensionFactory.new
            ef.config = OpenSSL::Config.parse(serialize[:conf])
            arg = ef.create_extension("crlDistributionPoints", serialize[:extension_string])
          end
          super(arg)

          @crl= R509::ASN1::GeneralNames.new
          data = R509::ASN1.get_extension_payload(self)
          data.entries.each do |distribution_point|
            #   DistributionPoint ::= SEQUENCE {
            #        distributionPoint       [0]     DistributionPointName OPTIONAL,
            #        reasons                 [1]     ReasonFlags OPTIONAL,
            #        cRLIssuer               [2]     GeneralNames OPTIONAL }
            #   DistributionPointName ::= CHOICE {
            #        fullName                [0]     GeneralNames,
            #        nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
            # We're only going to handle DistributionPointName [0] for now
            # so grab entries[0] and then get the fullName with value[0]
            # and the value of that ASN1Data with value[0] again
            @crl.add_item(distribution_point.entries[0].value[0].value[0])
          end
        end
      end

      # Implements the OCSP noCheck certificate extension
      class OCSPNoCheck < OpenSSL::X509::Extension
        # friendly name for OCSP No Check
        OID = "noCheck"
        Extensions.register_class(self)

        def initialize(arg=nil)
          if not arg.nil? and arg != false and not arg.kind_of?(OpenSSL::X509::Extension)
            ef = OpenSSL::X509::ExtensionFactory.new
            arg = ef.create_extension("noCheck","yes")
          end
          super(arg)
        end
      end


      # Implements the CertificatePolicies certificate extension, with methods to
      # provide access to the components and meaning of the extension's contents.
      class CertificatePolicies < OpenSSL::X509::Extension
        # friendly name for CP OID
        OID = "certificatePolicies"
        Extensions.register_class(self)
        attr_reader :policies

        def initialize(arg)
          if arg.kind_of?(Array)
            conf = []
            policy_names = ["ia5org"]
            arg.each_with_index do |policy,i|
              conf << build_conf("certPolicies#{i}",policy,i)
              policy_names << "@certPolicies#{i}"
            end
            ef = OpenSSL::X509::ExtensionFactory.new
            ef.config = OpenSSL::Config.parse(conf.join("\n"))
            arg = ef.create_extension("certificatePolicies", policy_names.join(","))
          end
          @policies = []
          super(arg)

          data = R509::ASN1.get_extension_payload(self)

          # each element of this sequence should be part of a policy + qualifiers
          #   certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
          data.each do |cp|
            @policies << R509::ASN1::PolicyInformation.new(cp)
          end if data.respond_to?(:each)
        end

        private
        def build_conf(section,hash,index)
          conf = ["[#{section}]"]
          conf.push "policyIdentifier=#{hash["policy_identifier"]}" unless hash["policy_identifier"].nil?
          hash["cps_uris"].each_with_index do |cps,idx|
            conf.push "CPS.#{idx+1}=\"#{cps}\""
          end if hash["cps_uris"].respond_to?(:each_with_index)

          user_notice_confs = []
          hash["user_notices"].each_with_index do |un,k|
            conf.push "userNotice.#{k+1}=@user_notice#{k+1}#{index}"
            user_notice_confs.push "[user_notice#{k+1}#{index}]"
            user_notice_confs.push "explicitText=\"#{un["explicit_text"]}\"" unless un["explicit_text"].nil?
            # if org is supplied notice numbers is also required (and vice versa). enforced in CAProfile
            user_notice_confs.push "organization=\"#{un["organization"]}\"" unless un["organization"].nil?
            user_notice_confs.push "noticeNumbers=\"#{un["notice_numbers"]}\"" unless un["notice_numbers"].nil?
          end unless not hash["user_notices"].kind_of?(Array)

          conf.concat(user_notice_confs)
          conf.join "\n"
        end
      end

      # Implements the InhibitAnyPolicy certificate extension, with methods to
      # provide access to the component and meaning of the extension's contents.
      class InhibitAnyPolicy < OpenSSL::X509::Extension
        # friendly name for CP OID
        OID = "inhibitAnyPolicy"
        Extensions.register_class(self)

        attr_reader :skip_certs

        def initialize(arg)
          if arg.kind_of?(Fixnum)
            ef = OpenSSL::X509::ExtensionFactory.new
            # must be set critical per RFC 5280
            arg = ef.create_extension("inhibitAnyPolicy",arg.to_s,true)
          end
          super(arg)

          #   id-ce-inhibitAnyPolicy OBJECT IDENTIFIER ::=  { id-ce 54 }
          #   InhibitAnyPolicy ::= SkipCerts
          #   SkipCerts ::= INTEGER (0..MAX)
          @skip_certs = R509::ASN1.get_extension_payload(self).to_i # returns a non-negative integer
        end
      end

      # Implements the PolicyConstraints certificate extension, with methods to
      # provide access to the components and meaning of the extension's contents.
      class PolicyConstraints < OpenSSL::X509::Extension
        # friendly name for CP OID
        OID = "policyConstraints"
        Extensions.register_class(self)

        attr_reader :require_explicit_policy
        attr_reader :inhibit_policy_mapping

        def initialize(arg)
          if arg.kind_of?(Hash)
            constraints = []
            constraints << "requireExplicitPolicy:#{arg['require_explicit_policy']}" unless arg['require_explicit_policy'].nil?
            constraints << "inhibitPolicyMapping:#{arg['inhibit_policy_mapping']}" unless arg['inhibit_policy_mapping'].nil?
            ef = OpenSSL::X509::ExtensionFactory.new
            arg = ef.create_extension("policyConstraints",constraints.join(","),true) # must be set critical per RFC 5280
          end
          super(arg)

          #   id-ce-policyConstraints OBJECT IDENTIFIER ::=  { id-ce 36 }
          #   PolicyConstraints ::= SEQUENCE {
          #        requireExplicitPolicy           [0] SkipCerts OPTIONAL,
          #        inhibitPolicyMapping            [1] SkipCerts OPTIONAL }
          #
          #   SkipCerts ::= INTEGER (0..MAX)
          data = R509::ASN1.get_extension_payload(self)
          data.each do |pc|
            if pc.tag == 0
              @require_explicit_policy = pc.value.bytes.to_a[0]
            elsif pc.tag == 1
              @inhibit_policy_mapping = pc.value.bytes.to_a[0]
            end
          end
        end
      end

      # Implements the NameConstraints certificate extension, with methods to
      # provide access to the components and meaning of the extension's contents.
      class NameConstraints < OpenSSL::X509::Extension
        # friendly name for CP OID
        OID = "nameConstraints"
        Extensions.register_class(self)

        attr_reader :permitted_names, :excluded_names

        #      id-ce-nameConstraints OBJECT IDENTIFIER ::=  { id-ce 30 }
        #      NameConstraints ::= SEQUENCE {
        #           permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
        #           excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
        #
        #      GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
        #
        # per RFC 5280
        # Within this profile, the minimum and maximum fields are not used with
        # any name forms, thus, the minimum MUST be zero, and maximum MUST be
        # absent
        #      GeneralSubtree ::= SEQUENCE {
        #           base                    GeneralName,
        #           minimum         [0]     BaseDistance DEFAULT 0,
        #           maximum         [1]     BaseDistance OPTIONAL }
        #
        #      BaseDistance ::= INTEGER (0..MAX)
        def initialize(arg)
          if arg.kind_of?(Hash)
            nc_data = []
            nc_conf = []
            if not arg["permitted"].nil?
              gns = R509::ASN1::GeneralNames.new
              arg["permitted"].each do |p|
                gns.create_item(:type => p["type"], :value => p["value"])
              end
              gns.names.each do |permitted|
                serialize = permitted.serialize_name
                nc_data.push "permitted;#{serialize[:extension_string]}"
                nc_conf.push serialize[:conf]
              end
            end
            if not arg["excluded"].nil?
              gns = R509::ASN1::GeneralNames.new
              arg["excluded"].each do |p|
                gns.create_item(:type => p["type"], :value => p["value"])
              end
              gns.names.each do |excluded|
                serialize = excluded.serialize_name
                nc_data.push "excluded;#{serialize[:extension_string]}"
                nc_conf.push serialize[:conf]
              end
            end

            ef = OpenSSL::X509::ExtensionFactory.new
            ef.config = OpenSSL::Config.parse nc_conf.join("\n")
            arg = ef.create_extension("nameConstraints",nc_data.join(","))
          end
          super(arg)

          @permitted_names = []
          @excluded_names = []

          data = R509::ASN1.get_extension_payload(self)
          data.each do |gs|
            gs.value.each do |asn_data|
              asn_data.value.each do |obj|
                gn = R509::ASN1::GeneralName.new(obj)
                if gs.tag == 0 # permittedSubtrees
                @permitted_names << gn
                elsif gs.tag == 1 #excludedSubtrees
                  @excluded_names << gn
                end
              end
            end
          end
        end
      end



      #
      # Helper class methods
      #

      # Takes OpenSSL::X509::Extension objects and wraps each in the appropriate
      # R509::Cert::Extensions object, and returns them in a hash. The hash is
      # keyed with the R509 extension class. Extensions without an R509
      # implementation are ignored (see #get_unknown_extensions).
      def self.wrap_openssl_extensions( extensions )
        r509_extensions = {}
        extensions.each do |openssl_extension|
          R509_EXTENSION_CLASSES.each do |r509_class|
            if ( r509_class::OID.downcase == openssl_extension.oid.downcase )
              if r509_extensions.has_key?(r509_class)
                raise ArgumentError.new("Only one extension object allowed per OID")
              end

              r509_extensions[r509_class] = r509_class.new( openssl_extension )
              break
            end
          end
        end

        return r509_extensions
      end

      # Given a list of OpenSSL::X509::Extension objects, returns those without
      # an R509 implementation.
      def self.get_unknown_extensions( extensions )
        unknown_extensions = []
        extensions.each do |openssl_extension|
          match_found = false
          R509_EXTENSION_CLASSES.each do |r509_class|
            if ( r509_class::OID.downcase == openssl_extension.oid.downcase )
              match_found = true
              break
            end
          end
          # if we make it this far (without breaking), we didn't match
          unknown_extensions << openssl_extension unless match_found
        end

        return unknown_extensions
      end
    end
  end
end

