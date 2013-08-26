require 'yaml'
require 'openssl'
require 'r509/exceptions'
require 'r509/io_helpers'
require 'r509/subject'
require 'r509/private_key'
require 'r509/engine'
require 'fileutils'
require 'pathname'

module R509
  # Module to contain all configuration related classes (e.g. CAConfig, CertProfile, SubjectItemPolicy)
  module Config
    # The Subject Item Policy allows you to define what subject fields are allowed in a
    # certificate. Required means that field *must* be supplied, optional means it will
    # be encoded if provided, and match means the field must be present and must match
    # the value specified.
    #
    # Using R509::OIDMapper you can create new shortnames that will be usable inside this class.
    class SubjectItemPolicy
      # @return [Array]
      attr_reader :required, :optional, :match, :match_values

      # @param [Hash] hash of required/optional/matching subject items. These must be in OpenSSL shortname format.
      # @example sample hash
      #  {"CN" => { :policy => "required" },
      #  "O" => { :policy => "required" },
      #  "OU" => { :policy => "optional" },
      #  "ST" => { :policy => "required" },
      #  "C" => { :policy => "required" },
      #  "L" => { :policy => "match", :value => "Chicago" },
      #  "emailAddress" => { :policy => "optional" }
      def initialize(hash={})
        if not hash.kind_of?(Hash)
          raise ArgumentError, "Must supply a hash in form 'shortname'=>hash_with_policy_info"
        end
        @required = []
        @optional = []
        @match_values = {}
        @match = []
        if not hash.empty?
          hash.each_pair do |key,value|
            if not value.kind_of?(Hash)
              raise ArgumentError, "Each value must be a hash with a :policy key"
            end
            case value[:policy]
            when 'required' then @required.push(key)
            when 'optional' then @optional.push(key)
            when 'match' then
              @match_values[key] = value[:value]
              @match.push(key)
            else
              raise ArgumentError, "Unknown subject item policy value. Allowed values are required, optional, or match"
            end
          end
        end
      end

      # @param [R509::Subject] subject
      # @return [R509::Subject] validated version of the subject or error
      def validate_subject(subject)
        # check if match components are present and match
        if not @match.empty?
          subject.to_a.each do |item|
            if @match.include?(item[0])
              if @match_values[item[0]] != item[1]
                raise R509::R509Error, "This profile requires that #{item[0]} have value: #{@match_values[item[0]]}"
              end
            end
          end
        end
        # convert the subject components into an array of component names that match
        # those that are on the required list
        supplied = subject.to_a.each do |item|
          @required.include?(item[0]) or @match.include?(item[0])
        end.map do |item|
          item[0]
        end
        # so we can make sure they gave us everything that's required
        diff = @required + @match - supplied
        if not diff.empty?
          raise R509::R509Error, "This profile requires you supply "+(@required+@match).join(", ")
        end

        # the validated subject contains only those subject components that are either
        # required, optional, or match
        R509::Subject.new(subject.to_a.select do |item|
          @required.include?(item[0]) or @optional.include?(item[0]) or @match.include?(item[0])
        end)
      end

      def to_h
        hash = {}
        @required.each { |r| hash[r] = {:policy => "required" } }
        @optional.each { |o| hash[o] = {:policy => "optional" } }
        @match.each { |m| hash[m] = {:policy => "match", :value => @match_values[m]} }
        hash
      end

      def to_yaml
        self.to_h.to_yaml
      end

    end
  end
end
