require 'r509/cert/extensions/base'

module R509
  class Cert
    module Extensions
      # RFC 5280 Description (see: http://www.ietf.org/rfc/rfc5280.txt)
      #
      # The name constraints extension, which MUST be used only in a CA
      # certificate, indicates a name space within which all subject names in
      # subsequent certificates in a certification path MUST be located.
      # Restrictions apply to the subject distinguished name and apply to
      # subject alternative names.  Restrictions apply only when the
      # specified name form is present.  If no name of the type is in the
      # certificate, the certificate is acceptable.
      #
      # Name constraints are not applied to self-issued certificates (unless
      # the certificate is the final certificate in the path).  (This could
      # prevent CAs that use name constraints from employing self-issued
      # certificates to implement key rollover.)
      #
      # Restrictions are defined in terms of permitted or excluded name
      # subtrees.  Any name matching a restriction in the excludedSubtrees
      # field is invalid regardless of information appearing in the
      # permittedSubtrees.  Conforming CAs MUST mark this extension as
      # critical and SHOULD NOT impose name constraints on the x400Address,
      # ediPartyName, or registeredID name forms.  Conforming CAs MUST NOT
      # issue certificates where name constraints is an empty sequence.  That
      # is, either the permittedSubtrees field or the excludedSubtrees MUST
      # be present.
      #
      # You can use this extension to parse an existing extension for easy access
      # to the contents or create a new one.
      class NameConstraints < OpenSSL::X509::Extension
        # friendly name for CP OID
        OID = "nameConstraints"
        Extensions.register_class(self)

        # @return [R509::ASN1::GeneralNames,nil]
        attr_reader :permitted, :excluded

        # @option arg :permitted [Array,R509::ASN1::GeneralNames] Array of hashes (see examples) or GeneralNames object
        # @option arg :excluded [Array,R509::ASN1::GeneralNames] Array of hashes (see examples) or GeneralNames object
        # @option arg :critical [Boolean] (false)
        # @example
        #   R509::Cert::Extensions::NameConstraints.new(
        #     :critical => false,
        #     :permitted => [
        #       { :type => 'dirName', :value => { :CN => 'myCN', :O => 'org' } }
        #     ]
        #   )
        # @example
        #   R509::Cert::Extensions::NameConstraints.new(
        #     :critical => false,
        #     :permitted => [
        #       { :type => 'dirName', :value => { :CN => 'myCN', :O => 'org' } }
        #     ],
        #     :excluded => [
        #       { :type => 'DNS', :value => 'domain.com' }
        #     ]
        #   )
        # @note When supplying IP you _must_ supply a full netmask in addition to an IP. (both IPv4 and IPv6 supported)
        # @note When supplying dirName the value is an R509::Subject or the hash used to build an R509::Subject
        #
        def initialize(arg)
          unless R509::Cert::Extensions.is_extension?(arg)
            arg = build_extension(arg)
          end
          super(arg)

          parse_extension
        end

        # @return [Hash]
        def to_h
          hash = { :critical => self.critical?  }
          hash[:permitted] = R509::Cert::Extensions.names_to_h(@permitted.names) unless @permitted.names.empty?
          hash[:excluded] = R509::Cert::Extensions.names_to_h(@excluded.names) unless @excluded.names.empty?
          hash
        end

        # @return [YAML]
        def to_yaml
          self.to_h.to_yaml
        end

        private

        def parse_extension
          @permitted = R509::ASN1::GeneralNames.new
          @excluded = R509::ASN1::GeneralNames.new

          data = R509::ASN1.get_extension_payload(self)
          data.each do |gs|
            gs.value.each do |asn_data|
              asn_data.value.each do |obj|
                gn = R509::ASN1::GeneralName.new(obj)
                if gs.tag == 0 # permittedSubtrees
                  @permitted.add_item(gn)
                elsif gs.tag == 1 # excludedSubtrees
                  @excluded.add_item(gn)
                end
              end
            end
          end
        end

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
        def build_extension(arg)
          validate_name_constraints(arg)
          nc_data = []
          nc_conf = []
          [:permitted, :excluded].each do |permit_exclude|
            unless arg[permit_exclude].nil?
              gns = R509::ASN1::GeneralNames.new
              arg[permit_exclude].each do |p|
                gns.create_item(p)
              end
              gns.names.each do |name|
                serialize = name.serialize_name
                nc_data.push "#{permit_exclude};#{serialize[:extension_string]}"
                nc_conf.push serialize[:conf]
              end
            end
          end

          ef = OpenSSL::X509::ExtensionFactory.new
          ef.config = OpenSSL::Config.parse nc_conf.join("\n")
          critical = R509::Cert::Extensions.calculate_critical(arg[:critical], true)
          # must be set critical per RFC 5280
          ef.create_extension("nameConstraints", nc_data.join(","), critical)
        end

        def validate_name_constraints(nc)
          unless nc.kind_of?(Hash)
            raise ArgumentError, "name_constraints must be provided as a hash"
          end
          [:permitted, :excluded].each do |key|
            unless nc[key].nil?
              validate_name_constraints_elements(key, nc[key])
            end
          end
          if (nc[:permitted].nil? || nc[:permitted].empty?) && (nc[:excluded].nil? || nc[:excluded].empty?)
            raise ArgumentError, "If name_constraints are supplied you must have at least one valid :permitted or :excluded element"
          end
        end

        def validate_name_constraints_elements(type, arr)
          unless arr.kind_of?(Array)
            raise ArgumentError, "#{type} must be an array"
          end
          arr.each do |el|
            if !el.kind_of?(Hash) || !el.key?(:type) || !el.key?(:value)
              raise ArgumentError, "Elements within the #{type} array must be hashes with both type and value"
            end
            if R509::ASN1::GeneralName.map_type_to_tag(el[:type]).nil?
              raise ArgumentError, "#{el[:type]} is not an allowed type. Check R509::ASN1::GeneralName.map_type_to_tag to see a list of types"
            end
          end
        end
      end
    end
  end
end
