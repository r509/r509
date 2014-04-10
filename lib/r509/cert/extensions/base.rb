require 'openssl'
require 'r509/asn1'
require 'set'

module R509
  class Cert
    # module to contain extension classes for R509::Cert
    module Extensions
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
              if r509_extensions.key?(r509_class)
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


      # Takes an array of R509::ASN1::GeneralName objects and returns a hash that can be
      # encoded to YAML (used by #to_yaml methods)
      def self.names_to_h(array)
        data = []
        array.each do |name|
          value = (name.value.kind_of?(R509::Subject))? name.value.to_h : name.value
          data.push(
            
              :type => name.short_type,
              :value => value
            
          )
        end
        data
      end

      # Mixed into extensions that have a single generalnames object to
      # simplify getting data out of them
      module GeneralNamesMixin
        # @return [Array<String>] DNS names
        def dns_names
          @general_names.dns_names
        end

        # @return [Array<String>] IP addresses. They will be formatted as strings (dotted quad with optional netmask for IPv4 and colon-hexadecimal with optional netmask for IPv6
        def ip_addresses
          @general_names.ip_addresses
        end
        alias_method :ips, :ip_addresses

        # @return [Array<String>] email addresses
        def rfc_822_names
          @general_names.rfc_822_names
        end
        alias_method :email_names, :rfc_822_names

        # @return [Array<String>] URIs (not typically found in SAN extensions)
        def uris
          @general_names.uris
        end

        # @return [Array<R509::Subject>] directory names
        def directory_names
          @general_names.directory_names
        end
        alias_method :dir_names, :directory_names

        # @return [Array] array of GeneralName objects preserving order found in the extension
        def names
          @general_names.names
        end
      end

      private
      R509_EXTENSION_CLASSES = Set.new

      # Registers a class as being an R509 certificate extension class. Registered
      # classes are used by #wrap_openssl_extensions to wrap OpenSSL extensions
      # in R509 extensions, based on the OID.
      def self.register_class( r509_ext_class )
        raise ArgumentError.new("R509 certificate extensions must have an OID") if r509_ext_class::OID.nil?
        R509_EXTENSION_CLASSES << r509_ext_class
      end

      def self.calculate_critical(critical,default)
        if critical.kind_of?(TrueClass) or critical.kind_of?(FalseClass)
          critical
        else
          default
        end
      end

      # Method attempts to determine if data being passed to an extension is already
      # an extension/asn.1 data or not.
      def self.is_extension?(data)
        return true if data.kind_of?(OpenSSL::X509::Extension)
        return false if not data.kind_of?(String)
        begin
          OpenSSL::X509::Extension.new(data)
          return true
        rescue
          return false
        end
      end

    end
  end
end
