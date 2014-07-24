# shared methods for validation among the extensions objects
module R509
  class Cert
    module Extensions
      # Validation methods shared by multiple extensions
      module ValidationMixin
        private

        # used by iap and pc validation methods
        def validate_non_negative_integer(source, value)
          if !value.is_a?(Integer) || value < 0
            raise ArgumentError, "#{source} must be a non-negative integer"
          end
          value
        end

        # validates key usage array
        def validate_usage(ku)
          if ku.nil? || !ku.is_a?(Hash) || !ku[:value].is_a?(Array)
            raise ArgumentError, 'You must pass a hash with a key :value that contains an array of strings (see README)'
          end
          ku
        end

        def validate_location(type, location)
          if location && !(location.is_a?(Array) || location.is_a?(R509::ASN1::GeneralNames))
            raise ArgumentError, "#{type} must contain an array or R509::ASN1::GeneralNames object if provided"
          end
          validate_general_name_hash_array(location) unless location.nil?
          location
        end

        def validate_general_name_hash_array(arr)
          arr.each do |l|
            if !l.is_a?(Hash) || l[:type].nil? || l[:value].nil?
              raise ArgumentError, "All elements of the array must be hashes with a :type and :value"
            end
          end unless arr.is_a?(R509::ASN1::GeneralNames)
        end
      end
    end
  end
end
