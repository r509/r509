# @private
# Intended as a mixin for Extensions and CertProfile to validate inbound data
module R509::ValidationMixin
  private
  # @private
  # validates subject item policy
  def validate_subject_item_policy(sip)
    if not sip.nil? and not sip.kind_of?(R509::Config::SubjectItemPolicy)
      raise ArgumentError, "subject_item_policy must be of type R509::Config::SubjectItemPolicy"
    end
    sip
  end

  # @private
  # validates key usage array
  def validate_key_usage(ku)
    if not ku.nil? and not ku.kind_of?(Array)
      raise ArgumentError, "key_usage must be an array of strings (see README)"
    end
    ku
  end

  # @private
  # validates inhibit any policy
  def validate_inhibit_any_policy(iap)
    if not iap.nil?
      validate_non_negative_integer("Inhibit any policy",iap)
    end
    iap
  end

  # @private
  def validate_policy_constraints(pc)
    if not pc.nil?
      if not pc.kind_of?(Hash)
        raise ArgumentError, 'Policy constraints must be provided as a hash with at least one of the two allowed keys: :inhibit_policy_mapping and :require_explicit_policy'
      end
      if not pc[:inhibit_policy_mapping].nil?
        ipm = validate_non_negative_integer("inhibit_policy_mapping",pc[:inhibit_policy_mapping])
      end
      if not pc[:require_explicit_policy].nil?
        rep = validate_non_negative_integer("require_explicit_policy",pc[:require_explicit_policy])
      end
      if not ipm and not rep
        raise ArgumentError, 'Policy constraints must have at least one of two keys: :inhibit_policy_mapping and :require_explicit_policy and the value must be non-negative'
      end
    end
    pc
  end

  # @private
  # used by iap and pc validation methods
  def validate_non_negative_integer(source,value)
      if not value.kind_of?(Integer) or value < 0
        raise ArgumentError, "#{source} must be a non-negative integer"
      end
      value
  end

  # @private
  # validates extended key usage array
  def validate_extended_key_usage(eku)
    if not eku.nil? and not eku.kind_of?(Array)
      raise ArgumentError, "extended_key_usage must be an array of strings (see README)"
    end
    eku
  end


  # @private
  # validates the structure of the certificate policies array
  def validate_certificate_policies(policies)
    if not policies.nil?
      if not policies.kind_of?(Array)
        raise ArgumentError, "Not a valid certificate policy structure. Must be an array of hashes"
      else
        policies.each do |policy|
          if policy[:policy_identifier].nil?
            raise ArgumentError, "Each policy requires a policy identifier"
          end
          if not policy[:cps_uris].nil?
            if not policy[:cps_uris].respond_to?(:each)
              raise ArgumentError, "CPS URIs must be an array of strings"
            end
          end
          if not policy[:user_notices].nil?
            if not policy[:user_notices].respond_to?(:each)
              raise ArgumentError, "User notices must be an array of hashes"
            else
              policy[:user_notices].each do |un|
                if not un[:organization].nil? and un[:notice_numbers].nil?
                  raise ArgumentError, "If you provide an organization you must provide notice numbers"
                end
                if not un[:notice_numbers].nil? and un[:organization].nil?
                  raise ArgumentError, "If you provide notice numbers you must provide an organization"
                end
              end
            end
          end
        end
      end
      policies
    end
  end

  # @private
  def validate_name_constraints(nc)
    if not nc.nil?
      if not nc.kind_of?(Hash)
        raise ArgumentError, "name_constraints must be provided as a hash"
      end
      [:permitted,:excluded].each do |key|
        if not nc[key].nil?
          validate_name_constraints_elements(key,nc[key])
        end
      end
      if (nc[:permitted].nil? or nc[:permitted].empty?) and (nc[:excluded].nil? or nc[:excluded].empty?)
        raise ArgumentError, "If name_constraints are supplied you must have at least one valid :permitted or :excluded element"
      end
    end
    nc
  end

  # @private
  def validate_name_constraints_elements(type,arr)
    if not arr.kind_of?(Array)
      raise ArgumentError, "#{type} must be an array"
    end
    arr.each do |el|
      if not el.kind_of?(Hash) or not el.has_key?(:type) or not el.has_key?(:value)
        raise ArgumentError, "Elements within the #{type} array must be hashes with both type and value"
      end
      if R509::ASN1::GeneralName.map_type_to_tag(el[:type]) == nil
        raise ArgumentError, "#{el[:type]} is not an allowed type. Check R509::ASN1::GeneralName.map_type_to_tag to see a list of types"
      end
    end
  end

  # @private
  # validates the structure of the certificate policies array
  def validate_basic_constraints(constraints)
    if not constraints.nil?
      if not constraints.respond_to?(:has_key?) or not constraints.has_key?(:ca)
        raise ArgumentError, "You must supply a hash with a key named :ca with a boolean value"
      end
      if constraints[:ca].nil? or (not constraints[:ca].kind_of?(TrueClass) and not constraints[:ca].kind_of?(FalseClass))
        raise ArgumentError, "You must supply true/false for the :ca key when specifying basic constraints"
      end
      if constraints[:ca] == false and not constraints[:path_length].nil?
        raise ArgumentError, ":path_length is not allowed when :ca is false"
      end
      if constraints[:ca] == true and not constraints[:path_length].nil? and (constraints[:path_length] < 0 or not constraints[:path_length].kind_of?(Integer))
        raise ArgumentError, "Path length must be a non-negative integer (>= 0)"
      end
    end
    constraints
  end

  # @private
  def validate_allowed_mds(allowed_mds)
    if allowed_mds.respond_to?(:each)
      allowed_mds = allowed_mds.map { |md| validate_md(md) }
      # case insensitively check if the default_md is in the allowed_mds
      # and add it if it's not there.
      if not allowed_mds.any?{ |s| s.casecmp(@default_md)==0 }
        allowed_mds.push @default_md
      end
    end
    allowed_mds
  end

  # @private
  def validate_md(md)
    md = md.upcase
    if not R509::MessageDigest::KNOWN_MDS.include?(md)
      raise ArgumentError, "An unknown message digest was supplied. Permitted: #{R509::MessageDigest::KNOWN_MDS.join(", ")}"
    end
    md
  end

  # @private
  def validate_cdp_location(location)
    if not location.nil? and not (location.kind_of?(Array) or location.kind_of?(R509::ASN1::GeneralNames))
      raise ArgumentError, "cdp_location must be an array or R509::ASN1::GeneralNames object if provided"
    end
    location
  end

  # @private
  def validate_ocsp_location(location)
    if not location.nil? and not (location.kind_of?(Array) or location.kind_of?(R509::ASN1::GeneralNames))
      raise ArgumentError, "ocsp_location must be an array or R509::ASN1::GeneralNames object if provided"
    end
    location
  end

  # @private
  def validate_ca_issuers_location(location)
    if not location.nil? and not (location.kind_of?(Array) or location.kind_of?(R509::ASN1::GeneralNames))
      raise ArgumentError, "ca_issuers_location must be an array or R509::ASN1::GeneralNames object if provided"
    end
    location
  end

  # @private
  def validate_subject_key_identifier(ski)
    if ski[:public_key].nil?
      raise ArgumentError, "You must supply a :public_key"
    end
    ski
  end

  # @private
  def validate_authority_key_identifier(aki)
    if aki[:issuer_certificate].nil? or not aki[:issuer_certificate].kind_of?(R509::Cert)
      raise ArgumentError, "You must supply an R509::Cert object to :issuer_certificate"
    end
    aki
  end

  # @private
  def validate_subject_alternative_name(san)
    if san.nil? or not (san.kind_of?(R509::ASN1::GeneralNames) or san.kind_of?(Array))
      raise ArgumentError, "You must supply an array or R509::ASN1::GeneralNames object to :names"
    end
  end
end
