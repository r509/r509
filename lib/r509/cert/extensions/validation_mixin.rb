# @private
# shared methods for validation among the extensions objects
module R509
  class Cert
    module Extensions
      module ValidationMixin
        private
        # @private
        # used by iap and pc validation methods
        def validate_non_negative_integer(source,value)
            if not value.kind_of?(Integer) or value < 0
              raise ArgumentError, "#{source} must be a non-negative integer"
            end
            value
        end

        # @private
        # validates key usage array
        def validate_usage(ku)
          if ku.nil? or not ku.kind_of?(Hash) or not ku[:value].kind_of?(Array)
            raise ArgumentError, 'You must pass a hash with a key :value that contains an array of strings (see README)'
          end
          ku
        end

        # @private
        def validate_location(type,location)
          if not location.nil? and not (location.kind_of?(Array) or location.kind_of?(R509::ASN1::GeneralNames))
            raise ArgumentError, "#{type} must be an array or R509::ASN1::GeneralNames object if provided"
          end
          location.each do |loc|
            if not loc.kind_of?(Hash) or loc[:type].nil? or loc[:value].nil?
              raise ArgumentError, "All elements of the array must be hashes with a :type and :value"
            end
          end unless not location.respond_to?(:each)
          location
        end
      end
    end
  end
end
