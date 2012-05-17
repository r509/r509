require 'openssl'
require 'set'

module R509
  class Cert
    module Extensions
      
      private
      R509_EXTENSION_CLASSES = Set.new
      
      def self.register_class( r509_ext_class )
        R509_EXTENSION_CLASSES << r509_ext_class
      end
      
      public
      class BasicConstraints < OpenSSL::X509::Extension
        OID = "basicConstraints"
        Extensions.register_class(self)
        
        attr_reader :path_length
        
        def initialize(*args)
          super(*args)
          
          @is_ca = ! ( self.value =~ /CA:TRUE/ ).nil?
          pathlen_match = self.value.match( /pathlen:(\d+)/ )
          @path_length = pathlen_match[1].to_i unless pathlen_match.nil?
        end
        
        def is_ca?()
          return @is_ca == true
        end
        
        def allows_sub_ca?()
          return false if @path_length.nil?
          return @path_length > 0
        end
      end
      
      class KeyUsage < OpenSSL::X509::Extension
        OID = "keyUsage"
        Extensions.register_class(self)
        
        AU_DIGITAL_SIGNATURE = "Digital Signature"
        AU_NON_REPUDIATION = "Non Repudiation"
        AU_KEY_ENCIPHERMENT = "Key Encipherment"
        AU_DATA_ENCIPHERMENT = "Data Encipherment"
        AU_KEY_AGREEMENT = "Key Agreement"
        AU_CERTIFICATE_SIGN = "Certificate Sign"
        AU_CRL_SIGN = "CRL Sign"
        AU_ENCIPHER_ONLY = "Encipher Only"
        AU_DECIPHER_ONLY = "Decipher Only"
        
        attr_reader :allowed_uses
        
        def initialize(*args)
          super(*args)
          
          @allowed_uses = self.value.split(",").map {|use| use.strip}
        end
        
        def allows?( friendly_use_name )
          @allowed_uses.include?( friendly_use_name )
        end
        
        def digital_signature?
          allows?( AU_DIGITAL_SIGNATURE )
        end
        
        def non_repudiation?
          allows?( AU_NON_REPUDIATION )
        end
        
        def key_encipherment?
          allows?( AU_KEY_ENCIPHERMENT )
        end
        
        def data_encipherment?
          allows?( AU_DATA_ENCIPHERMENT )
        end
        
        def key_agreement?
          allows?( AU_KEY_AGREEMENT )
        end
        
        def certificate_sign?
          allows?( AU_CERTIFICATE_SIGN )
        end
        
        def crl_sign?
          allows?( AU_CRL_SIGN )
        end
        
        def encipher_only?
          allows?( AU_ENCIPHER_ONLY )
        end
        
        def decipher_only?
          allows?( AU_DECIPHER_ONLY )
        end
      end
      
      class ExtendedKeyUsage < OpenSSL::X509::Extension
        OID = "extendedKeyUsage"
        Extensions.register_class(self)
        
        AU_WEB_SERVER_AUTH = "TLS Web Server Authentication"
        AU_WEB_CLIENT_AUTH = "TLS Web Client Authentication"
        AU_CODE_SIGNING = "Code Signing"
        AU_EMAIL_PROTECTION = "E-mail Protection"
        
        attr_reader :allowed_uses
        
        def initialize(*args)
          super(*args)
          
          @allowed_uses = self.value.split(",").map {|use| use.strip}
        end
        
        def allows?( friendly_use_name )
          @allowed_uses.include?( friendly_use_name )
        end
        
        def web_server_authentication?
          allows?( AU_WEB_SERVER_AUTH )
        end
        
        def web_client_authentication?
          allows?( AU_WEB_CLIENT_AUTH )
        end
        
        def code_signing?
          allows?( AU_CODE_SIGNING )
        end
        
        def email_protection?
          allows?( AU_EMAIL_PROTECTION )
        end
        
        # ...
      end
      
      class SubjectKeyIdentifier < OpenSSL::X509::Extension
        OID = "subjectKeyIdentifier"
        Extensions.register_class(self)
        
        def key()
          return self.value
        end
      end
      
      class AuthorityKeyIdentifier < OpenSSL::X509::Extension
        OID = "authorityKeyIdentifier"
        Extensions.register_class(self)
        
      end
      
      class SubjectAlternativeName < OpenSSL::X509::Extension
        OID = "subjectAltName"
        Extensions.register_class(self)
        
        attr_reader :dns_names
        attr_reader :ip_addresses
        attr_reader :uris
        
        def initialize(*args)
          super(*args)
          
          @dns_names = self.value.scan( /DNS:([^,]+)/ ).map { |match| match[0] }
          @ip_addresses = self.value.scan( /IP:([^,]+)/ ).map { |match| match[0] }
          @uris = self.value.scan( /URI:([^,]+)/ ).map { |match| match[0] }
        end
      end
      
      class AuthorityInfoAccess < OpenSSL::X509::Extension
        OID = "authorityInfoAccess"
        Extensions.register_class(self)
        
        attr_reader :ocsp_uri
        attr_reader :ca_issuers_uri
        
        def initialize(*args)
          super(*args)
          
          uri_match = self.value.match( /OCSP - URI:(http[^\n ]*)/ )
          @ocsp_uri = uri_match[1] unless uri_match.nil?
          uri_match = self.value.match( /CA Issuers - URI:(http[^\n ]*)/ )
          @ca_issuers_uri = uri_match[1] unless uri_match.nil?
        end
      end
      
      class CrlDistributionPoints < OpenSSL::X509::Extension
        OID = "crlDistributionPoints"
        Extensions.register_class(self)
        
        attr_reader :crl_uri
        
        def initialize(*args)
          super(*args)
          
          uri_match = self.value.match( /URI:(http[^\n ]*)/ )
          @crl_uri = uri_match[1] unless uri_match.nil?
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
  