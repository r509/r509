require "openssl"

module R509
  # The primary subject class. Used for building subject DNs in a sane fashion.
  # @example
  #   subject = R509::Subject.new
  #   subject.CN= "test.test"
  #   subject.organization= "r509 LLC"
  # @example
  #   subject = R509::Subject.new([['CN','test.test'],['O','r509 LLC']])
  # @example
  #   subject = R509::Subject.new(:CN => 'test.test', :O => 'r509 LLC')
  # @example
  #   # you can also use the friendly getter/setters with custom OIDs
  #   R509::OIDMapper.register("1.2.3.4.5.6.7.8","COI","customOID")
  #   subject = R509::Subject.new
  #   subject.COI="test"
  #   # or
  #   subject.customOID="test"
  #   # or
  #   subject.custom_oid="test"
  class Subject
    # @param [Array, OpenSSL::X509::Name, R509::Subject, DER, Hash, nil] arg
    def initialize(arg=nil)
      if arg.kind_of?(Array)
        @array = arg
      elsif arg.kind_of?(Hash)
        @array = arg.map { |k,v| [k.to_s.upcase,v] }
      elsif arg.kind_of?(OpenSSL::X509::Name)
        sanitizer = R509::NameSanitizer.new
        @array = sanitizer.sanitize(arg)
      elsif arg.kind_of?(R509::Subject)
        @array = arg.to_a
      else
        @array = []
        unless (begin OpenSSL::ASN1.decode(arg) rescue nil end).nil?
          parse_asn1(arg)
        end
      end

      # see if X509 thinks this is okay
      name
    end

    # @return [OpenSSL::X509::Name]
    def name
      OpenSSL::X509::Name.new(@array)
    end

    # @return [Boolean]
    def empty?
      @array.empty?
    end

    # get value for key
    def [](key)
      @array.each do |item|
        if key == item[0]
          return item[1]
        end
      end
      return nil
    end

    # set key and value
    def []=(key, value)
      added = false
      @array = @array.map do |item|
        if key == item[0]
          added = true
          [key, value]
        else
          item
        end
      end

      unless added
        @array << [key, value]
      end

      # see if X509 thinks this is okay
      name

      @array
    end

    # @param [String] key item you want deleted
    def delete(key)
      @array = @array.select do |item|
        item[0] != key
      end
    end

    # @return [String] string of form /CN=something.com/O=whatever/L=Locality
    def to_s
      name.to_s
    end

    # @return [Array] Array of form [['CN','langui.sh']]
    def to_a
      @array
    end

    # @return [Hash]
    def to_h
      hash = {}
      @array.each do |el|
        hash[el[0].to_sym] = el[1]
      end
      hash
    end

    # @return [YAML]
    def to_yaml
      self.to_h.to_yaml
    end

    # @private
    def respond_to?(method_sym, include_private = false)
      method_sym.to_s =~ /([^=]*)/
      oid = oid_check($1)
      if not oid.nil?
        true
      else
        super(method_sym, include_private)
      end
    end

    private

    # Try to build methods for getting/setting various subject attributes
    # dynamically. this will also cache methods that get built via instance_eval.
    # This code will also allow you to set subject items for custom oids
    # defined via R509::OIDMapper
    #
    # @example
    #  subject = R509::Subject.new
    #  subject.CN = 'test' # method built via method missing.
    #
    def method_missing(method_sym, *args, &block)
      if method_sym.to_s =~ /(.*)=$/
        sn = oid_check($1)
        if not sn.nil?
          define_dynamic_setter(method_sym,sn)
          send(method_sym, args.first)
        else
          return super(method_sym, *args, &block)
        end
      else
        sn = oid_check(method_sym)
        if not sn.nil?
          define_dynamic_getter(method_sym,sn)
          send(method_sym)
        else
          return super(method_sym, *args, &block)
        end
      end
    end

    def define_dynamic_setter(name,sn)
      instance_eval <<-RUBY
        def #{name.to_s}(value)
          self["#{sn}"]= value
        end
      RUBY
    end

    def define_dynamic_getter(name,sn)
      instance_eval <<-RUBY
        def #{name.to_s}
          self["#{sn}"]
        end
      RUBY
    end

    def oid_check(name)
      oid = OpenSSL::ASN1::ObjectId.new(camelize(name))
      oid.short_name
    end

    def camelize(sym)
      sym.to_s.split('_').reduce([]){ |buffer,e| buffer.push(buffer.empty? ? e : e.capitalize) }.join
    end

    def parse_asn1(asn)
      asn = OpenSSL::ASN1.decode asn
      # parsing a subject DN
      # We have to iterate a sequence, which holds sets. Each set has one value: a sequence, which has 2 values
      # So it's effectively an array of arrays which each have only one element, which is an array of 2 values.
      asn.value.each do |set|
        sn = set.value.first.value.first.value
        val = set.value.first.value.last.value
        self[sn] = val
      end
    end
  end

  # Sanitize an X509::Name. The #to_a method replaces unknown OIDs with "UNDEF", but the #to_s
  # method doesn't. What we want to do is build the array that would have been produced by #to_a
  # if it didn't throw away the OID.
  # This method is not required as of ruby-1.9.3p125 and up.
  class NameSanitizer
    # @option name [OpenSSL::X509::Name]
    # @return [Array] array of the form [["OID", "VALUE], ["OID", "VALUE"]] with "UNDEF" replaced by the actual OID
    def sanitize(name)
      line = name.to_s
      array = name.to_a.dup
      used_oids = []
      undefined_components(array).each do |component|
        begin
          # get the OID from the subject line that has this value
          oids = line.scan(/\/([\d\.]+)=#{component[:value]}/).flatten
          if oids.size == 1
            oid = oids.first
          else
            oid = oids.select{ |match| not used_oids.include?(match) }.first
          end
          # replace the "UNDEF" OID name in the array at the index the UNDEF was found
          array[component[:index]][0] = oid
          # remove the first occurrence of this in the subject line (so we can handle the same oid/value pair multiple times)
          line = line.sub("/#{oid}=#{component[:value]}", "")
          # we record which OIDs we've used in case two different unknown OIDs have the same value
          used_oids << oid
        rescue
          # I don't expect this to happen, but if it does we'll just not replace UNDEF and continue
        end
      end
      array
    end

    private

    # get the components from #to_a that are UNDEF
    # @option array [Array<OpenSSL::X509::Name>]
    # @return [Hash]
    # @example
    #  Return value looks like
    #  { :index => the index in the original array where we found an UNDEF, :value => the subject component value }
    def undefined_components(array)
      components = []
      array.each_index do |index|
        components << { :index => index, :value => array[index][1] } if array[index][0] == "UNDEF"
      end
      components
    end
  end
end
