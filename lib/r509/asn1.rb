require 'ipaddr'

module R509
  # Module for holding various classes related to parsed ASN.1 objects
  module ASN1
    # parses the ASN.1 payload and gets the extension data out for further processing
    # by the subclasses
    def self.get_extension_payload(ext)
      asn = OpenSSL::ASN1.decode ext
      # Our extension object. Here's the structure:
      #   Extension  ::=  SEQUENCE  {
      #        extnID      OBJECT IDENTIFIER,
      #        critical    BOOLEAN DEFAULT FALSE,
      #        extnValue   OCTET STRING
      #                    -- contains the DER encoding of an ASN.1 value
      #                    -- corresponding to the extension type identified
      #                    -- by extnID
      #        }
      OpenSSL::ASN1.decode(asn.entries.last.value).value
    end

    # @param [Array] names An array of strings. Can be dNSName, iPAddress, URI, or rfc822Name.
    #   You can also supply a directoryName, but this must be an R509::Subject or array of arrays
    # @return [R509::ASN1::GeneralNames]
    def self.general_name_parser(names)
      if names.nil?
        return nil
      elsif names.kind_of?(R509::ASN1::GeneralNames)
        return names
      elsif not names.kind_of?(Array)
        raise ArgumentError, "You must supply an array or existing R509::ASN1 GeneralNames object to general_name_parser"
      end
      general_names = R509::ASN1::GeneralNames.new
      names.uniq!
      names.map do |domain|
        if !(IPAddr.new(domain.strip) rescue nil).nil?
          ip = IPAddr.new(domain.strip)
          general_names.create_item(:tag => 7, :value => ip.to_s)
        else
          case domain
          when R509::Subject, Array
            subject = R509::Subject.new(domain)
            general_names.create_item(:tag => 4, :value => subject)
          when /:\/\// #URI
            general_names.create_item(:tag => 6, :value => domain.strip)
          when /@/ #rfc822Name
            general_names.create_item(:tag => 1, :value => domain.strip)
          else #dNSName
            general_names.create_item(:tag => 2, :value => domain.strip)
          end
        end
      end
      general_names
    end

    # This class parses ASN.1 GeneralName objects. At the moment it supports
    # rfc822Name, dNSName, directoryName, uniformResourceIdentifier, and iPAddress
    #   GeneralName ::= CHOICE {
    #        otherName                       [0]     OtherName,
    #        rfc822Name                      [1]     IA5String,
    #        dNSName                         [2]     IA5String,
    #        x400Address                     [3]     ORAddress,
    #        directoryName                   [4]     Name,
    #        ediPartyName                    [5]     EDIPartyName,
    #        uniformResourceIdentifier       [6]     IA5String,
    #        iPAddress                       [7]     OCTET STRING,
    #        registeredID                    [8]     OBJECT IDENTIFIER }
    class GeneralName
      # The type, represented as a symbolized version of the GeneralName (e.g. :dNSName)
      attr_reader :type
      # The prefix OpenSSL needs for this type when encoding it into an extension.
      attr_reader :serial_prefix
      # Value of the GeneralName
      attr_reader :value
      # Integer tag type. See GeneralName description at the top of this class
      attr_reader :tag

      # @param [OpenSSL::ASN1::ASN1Data,Hash] asn ASN.1 input data. Can also pass a hash with :tag and :value keys
      def initialize(asn)
        if asn.kind_of?(Hash) and asn.has_key?(:tag) and asn.has_key?(:value)
          # this is added via create_item
          @tag = asn[:tag]
          @type = R509::ASN1::GeneralName.map_tag_to_type(@tag)
          @serial_prefix = R509::ASN1::GeneralName.map_tag_to_serial_prefix(@tag)
          @value = asn[:value]
        else
          @tag = asn.tag
          @type = R509::ASN1::GeneralName.map_tag_to_type(@tag)
          @serial_prefix = R509::ASN1::GeneralName.map_tag_to_serial_prefix(@tag)
          value = asn.value
          case @tag
          when 1 then @value = value
          when 2 then @value = value
          when 4 then @value = R509::Subject.new(value.first.to_der)
          when 6 then @value = value
          when 7
            if value.size == 4 or value.size == 16
              ip = IPAddr.new_ntoh(value)
              @value = ip.to_s
            elsif value.size == 8 #IPv4 with netmask
              ip = IPAddr.new_ntoh(value[0,4])
              netmask = IPAddr.new_ntoh(value[4,4])
              @value = ip.to_s + "/" + netmask.to_s
            elsif value.size == 32 #IPv6 with netmask
              ip = IPAddr.new_ntoh(value[0,16])
              netmask = IPAddr.new_ntoh(value[16,16])
              @value = ip.to_s + "/" + netmask.to_s
            end
          end
        end
      end

      # Maps a GeneralName type to the integer tag representation
      # @param [String,Symbol] type of GeneralName
      # @return [Integer] tag for the type
      def self.map_type_to_tag(type)
        #        otherName                       [0]     OtherName,
        #        rfc822Name                      [1]     IA5String,
        #        dNSName                         [2]     IA5String,
        #        x400Address                     [3]     ORAddress,
        #        directoryName                   [4]     Name,
        #        ediPartyName                    [5]     EDIPartyName,
        #        uniformResourceIdentifier       [6]     IA5String,
        #        iPAddress                       [7]     OCTET STRING,
        #        registeredID                    [8]     OBJECT IDENTIFIER }
        case type
        when "otherName", :otherName then 0
        when "rfc822Name", :rfc822Name, "email" then 1
        when "dNSName", :dNSName, "DNS" then 2
        when "x400Address", :x400Address then 3
        when "directoryName", :directoryName, "dirName" then 4
        when "ediPartyName", :ediPartyName  then 5
        when "uniformResourceIdentifier", :uniformResourceIdentifier, "URI" then 6
        when "iPAddress", :iPAddress, "IP" then 7
        when "registeredID", :registeredID  then 8
        end
      end

      # @param [Integer] tag
      # @return [String] serial prefix
      def self.map_tag_to_serial_prefix(tag)
        case tag
        when 1 then "email"
        when 2 then "DNS"
        when 4 then "dirName"
        when 6 then "URI"
        when 7 then "IP"
        else
          raise R509Error, "Unimplemented GeneralName tag: #{tag}. At this time R509 does not support GeneralName types other than rfc822Name, dNSName, uniformResourceIdentifier, iPAddress, and directoryName"
        end
      end

      # @param [Integer] tag
      # @return [Symbol] symbol type
      def self.map_tag_to_type(tag)
        case tag
        when 0 then :otherName
        when 1 then :rfc822Name
        when 2 then :dNSName
        when 3 then :x400Address
        when 4 then :directoryName
        when 5 then :ediPartyName
        when 6 then :uniformResourceIdentifier
        when 7 then :iPAddress
        when 8 then :registeredID
        else
          raise R509Error, "Invalid tag #{tag}"
        end
      end

      # @private
      # required for #uniq comparisons
      # @return [Boolean] equality between objects
      def ==(other)
        (other.class == self.class and self.type == other.type && self.value == other.value)
      end
      alias_method :eql?, :==

      # @private
      # required for #uniq comparisons
      def hash
        "#{self.type}#{self.tag}#{self.value}".hash
      end

      # Used to serialize GeneralName objects when issuing new certificates inside R509::CertificateAuthority::Signer
      # @return [Hash] conf section and name serialized for OpenSSL extension creation
      def serialize_name
        if self.type == :directoryName
          return serialize_directory_name
        else
          extension_string = self.serial_prefix + ":" + self.value
          return { :conf => nil, :extension_string => extension_string }
        end
      end

      private
      # @private
      # Serializes directory names.
      def serialize_directory_name
        conf_name = OpenSSL::Random.random_bytes(16).unpack("H*")[0]
        conf = ["[#{conf_name}]"]
        @value.to_a.each do |el|
          conf << "#{el[0]}=#{el[1]}"
        end
        conf = conf.join("\n")
        extension_string = self.serial_prefix + ":" + conf_name
        { :conf => conf, :extension_string => extension_string }
      end
    end

    # object to hold parsed sequences of generalnames
    # these structures are used in SubjectAlternativeName, AuthorityInfoAccess, CRLDistributionPoints, etc
    class GeneralNames
      def initialize
        @types = {
          :otherName => [], # unimplemented
          :rfc822Name => [],
          :dNSName => [],
          :x400Address => [], # unimplemented
          :directoryName => [],
          :ediPartyName => [], # unimplemented
          :uniformResourceIdentifier => [],
          :iPAddress => [],
          :registeredID => [] # unimplemented
        }
        @ordered_names = []
      end

      # @param [OpenSSL::ASN1::ASN1Data] asn Takes ASN.1 data in for parsing GeneralName structures
      def add_item(asn)
        # map general names into our hash of arrays
        if asn.kind_of?(R509::ASN1::GeneralName)
          @ordered_names << asn
          @types[asn.type] << asn.value
        else
          gn = R509::ASN1::GeneralName.new(asn)
          @ordered_names << gn
          @types[gn.type] << gn.value
        end
      end

      # @param [Hash] hash A hash with (:tag or :type) and :value keys. Allows you to build GeneralName objects and add
      #   them to the GeneralNames object. Unless you know what you're doing you should really stay away from this.
      def create_item(hash)
        if not hash.respond_to?(:has_key?) or (not hash.has_key?(:tag) and not hash.has_key?(:type)) or not hash.has_key?(:value)
          raise ArgumentError, "Must be a hash with (:tag or :type) and :value nodes"
        end
        if hash[:type]
          hash[:tag] = R509::ASN1::GeneralName.map_type_to_tag(hash[:type])
        end
        gn = R509::ASN1::GeneralName.new(:tag => hash[:tag], :value => hash[:value])
        add_item(gn)
      end

      # @return [Array] array of GeneralName objects
      # order found in the extension
      def names
        @ordered_names
      end

      # @return [Array] Array of rfc822name strings
      def rfc_822_names
        @types[:rfc822Name]
      end

      # @return [Array] Array of dnsName strings
      def dns_names
        @types[:dNSName]
      end

      # @return [Array] Array of uri strings
      def uniform_resource_identifiers
        @types[:uniformResourceIdentifier]
      end
      alias_method :uris, :uniform_resource_identifiers

      # @return [Array] Array of IP address strings
      def ip_addresses
        @types[:iPAddress]
      end

      # @return [Array] Array of directoryNames (R509::Subject objects)
      def directory_names
        @types[:directoryName]
      end

      # @return [Array] string of serialized names for OpenSSL extension creation
      def serialize_names
        confs = []
        extension_strings = []
        @ordered_names.each { |item|
          data = item.serialize_name
          confs << data[:conf]
          extension_strings << data[:extension_string]
        }
        { :conf => confs.join("\n"), :extension_string => extension_strings.join(",") }
      end
    end

    #   PolicyInformation ::= SEQUENCE {
    #        policyIdentifier   CertPolicyId,
    #        policyQualifiers   SEQUENCE SIZE (1..MAX) OF
    #                                PolicyQualifierInfo OPTIONAL }
    class PolicyInformation
      attr_reader :policy_identifier, :policy_qualifiers
      def initialize(data)
        # store the policy identifier OID
        @policy_identifier = data.entries[0].value
        # iterate the policy qualifiers if any exist
        if not data.entries[1].nil?
          @policy_qualifiers = PolicyQualifiers.new
          data.entries[1].each do |pq|
            @policy_qualifiers.parse(pq)
          end
        end
      end
    end

    #   PolicyQualifierInfo ::= SEQUENCE {
    #        policyQualifierId  PolicyQualifierId,
    #        qualifier          ANY DEFINED BY policyQualifierId }
    class PolicyQualifiers
      attr_reader :cps_uris, :user_notices
      def initialize
        @cps_uris = []
        @user_notices = []
      end

      # parse each PolicyQualifier and store the results into the object array
      def parse(data)
        oid = data.entries[0].value
        case
        when oid == 'id-qt-cps'
          @cps_uris << data.entries[1].value
        when oid == 'id-qt-unotice'
          @user_notices <<  UserNotice.new(data.entries[1])
        end
      end
    end

    #   UserNotice ::= SEQUENCE {
    #        noticeRef        NoticeReference OPTIONAL,
    #        explicitText     DisplayText OPTIONAL }
    class UserNotice
      attr_reader :notice_reference, :explicit_text
      def initialize(data)
        data.each do |qualifier|
          #if we find another sequence, that's a noticeReference, otherwise it's explicitText
          if qualifier.kind_of?(OpenSSL::ASN1::Sequence)
            @notice_reference = NoticeReference.new(qualifier)
          else
            @explicit_text = qualifier.value
          end

        end if data.respond_to?(:each)
      end
    end

    #   NoticeReference ::= SEQUENCE {
    #        organization     DisplayText,
    #        noticeNumbers    SEQUENCE OF INTEGER }
    class NoticeReference
      attr_reader :organization, :notice_numbers
      def initialize(data)
        data.each do |notice_reference|
          # if it's displaytext then it's the organization
          # if it's YET ANOTHER ASN1::Sequence, then it's noticeNumbers
          if notice_reference.kind_of?(OpenSSL::ASN1::Sequence)
            @notice_numbers = []
            notice_reference.each do |ints|
              @notice_numbers << ints.value.to_i
            end
          else
            @organization = notice_reference.value
          end
        end
      end
    end

  end
end
