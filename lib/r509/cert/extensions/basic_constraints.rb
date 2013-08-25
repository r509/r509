require 'r509/cert/extensions/base'

module R509
  class Cert
    module Extensions
      # RFC 5280 Description (see: http://www.ietf.org/rfc/rfc5280.txt)
      #
      # The basic constraints extension identifies whether the subject of the
      # certificate is a CA and the maximum depth of valid certification
      # paths that include this certificate.
      #
      # You can use this extension to parse an existing extension for easy access
      # to the contents or create a new one.
      class BasicConstraints < OpenSSL::X509::Extension
        include R509::ValidationMixin

        # friendly name for BasicConstraints OID
        OID = "basicConstraints"
        Extensions.register_class(self)

        # returns the path length (if present)
        # @return [Integer,nil]
        attr_reader :path_length

        # This method takes a hash or an existing Extension object to parse
        # @option arg :ca [Boolean]
        # @option arg :path_length optional [Integer]
        # @option arg :critical [Boolean] (true)
        def initialize(arg)
          if arg.kind_of?(Hash)
            arg = build_extension(arg)
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

        # Check whether the extension value would make the parent certificate a CA
        # @return [Boolean]
        def is_ca?
          return @is_ca == true
        end

        # Returns true if the path length allows this certificate to be used to
        # create subordinate signing certificates beneath it. Does not check if
        # there is a pathlen restriction in the cert chain above the current cert
        # @return [Boolean]
        def allows_sub_ca?
          return false unless is_ca?
          return true if @path_length.nil?
          return @path_length > 0
        end

        # @return [Hash]
        def to_h
          hash = { :ca => @is_ca, :critical => self.critical? }
          hash[:path_length] = @path_length unless @path_length.nil? or not is_ca?
          hash
        end

        # @return [YAML]
        def to_yaml
          self.to_h.to_yaml
        end

        private

        # @private
        def build_extension(arg)
          validate_basic_constraints(arg)
          ef = OpenSSL::X509::ExtensionFactory.new
          if arg[:ca] == true
            bc_value = "CA:TRUE"
            if not arg[:path_length].nil?
              bc_value += ",pathlen:#{arg[:path_length]}"
            end
          else
            bc_value = "CA:FALSE"
          end
          critical = R509::Cert::Extensions.calculate_critical(arg[:critical], true)
          return ef.create_extension("basicConstraints", bc_value, critical)
        end
      end
    end
  end
end
