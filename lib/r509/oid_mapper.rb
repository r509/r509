require 'openssl'

module R509
  # Helps map raw OIDs to friendlier short names
  module OIDMapper
    # Register an OID so we have a friendly short name
    # @param [String] oid A string representation of the OID you want to map (e.g. "1.6.2.3.55")
    # @param [String] short_name The short name (e.g. CN, O, OU, emailAddress)
    # @param [String] long_name Optional long name. Defaults to the same as short_name
    # @return [Boolean] success/failure
    def self.register(oid, short_name, long_name = nil)
      if long_name.nil?
        long_name = short_name
      end
      OpenSSL::ASN1::ObjectId.register(oid, short_name, long_name)
    end

    # Register a batch of OIDs so we have friendly short names
    # @param [Array] oids An array of hashes
    # @example
    #  R509::OIDMapper.batch_register([
    #   {:oid => "1.2.3.4.5", :short_name => "sName", :long_name => "lName"},
    #   {:oid => "1.2.3.4.6", :short_name => "oName"}
    # ]
    def self.batch_register(oids)
      oids.each do |oid_hash|
        self.register(oid_hash[:oid], oid_hash[:short_name], oid_hash[:long_name])
      end
      nil
    end

    # Load YAML and register OIDs
    # @param [String] name Name of the config within the file
    # @param [String] yaml_data YAML data to load
    # @example
    #  custom_oids:
    #    - :oid: 1.4.3.2.1.2.3.4.4.4.5
    #      :short_name: testOIDName
    #    - :oid: 1.4.3.2.1.2.5.4.4.4.5
    #      :short_name: anotherOIDName
    def self.register_from_yaml(name, yaml_data)
      conf = YAML.load(yaml_data)
      self.batch_register(conf[name])
    end
  end
end
