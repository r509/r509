# Mixed into extensions that have a single generalnames object to
# simplify getting data out of them
module R509
  class Cert
    module Extensions
      module GeneralNamesMixin
        # @return [Array<String>] DNS names
        def dns_names
          @general_names.dns_names
        end

        # @return [Array<String>] IP addresses formatted as dotted quad
        def ip_addresses
          @general_names.ip_addresses
        end
        alias :ips :ip_addresses

        # @return [Array<String>] email addresses
        def rfc_822_names
          @general_names.rfc_822_names
        end
        alias :email_names :rfc_822_names

        # @return [Array<String>] URIs (not typically found in SAN extensions)
        def uris
          @general_names.uris
        end

        # @return [Array<R509::Subject>] directory names
        def directory_names
          @general_names.directory_names
        end
        alias :dir_names :directory_names

        # @return [Array] array of GeneralName objects preserving order found in the extension
        def names
          @general_names.names
        end
      end
    end
  end
end
