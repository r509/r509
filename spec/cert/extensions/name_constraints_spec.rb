require 'spec_helper'

include R509::Cert::Extensions

shared_examples_for "a correct R509 NameConstraints object" do |critical|
  before :all do
    extension_name = "nameConstraints"
    klass = NameConstraints
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.config = OpenSSL::Config.parse(@conf)
    openssl_ext = ef.create_extension( extension_name, @extension_value, critical)
    @r509_ext = klass.new( openssl_ext )
  end

  it "should have the permitted names" do
    @permitted.each_with_index do |name,index|
      @r509_ext.permitted.names[index].tag.should == name[:tag]
      @r509_ext.permitted.names[index].value.should == name[:value]
    end
  end
  it "should have the excluded names" do
    @excluded.each_with_index do |name,index|
      @r509_ext.excluded.names[index].tag.should == name[:tag]
      @r509_ext.excluded.names[index].value.should == name[:value]
    end
  end
end

describe R509::Cert::Extensions::NameConstraints do
  include R509::Cert::Extensions

  context "validate name constraints"do
    it "raises an error when not a hash" do
      expect { R509::Cert::Extensions::NameConstraints.new( 'a string' ) }.to raise_error(ArgumentError,'name_constraints must be provided as a hash')
    end

    it "raises an error when permitted and excluded are empty" do
      expect { R509::Cert::Extensions::NameConstraints.new( :permitted => [], :excluded => [] ) }.to raise_error(ArgumentError,'If name_constraints are supplied you must have at least one valid :permitted or :excluded element')
    end

    it "raises an error when permitted or excluded are not arrays" do
      expect { R509::Cert::Extensions::NameConstraints.new( :permitted => 'string', :excluded => 'string' ) }.to raise_error(ArgumentError,'permitted must be an array')
    end

    it "raises an error when permitted or excluded elements are not hashes with the required values" do
      expect { R509::Cert::Extensions::NameConstraints.new( :permitted => [{"type" => 'DNS'}] ) }.to raise_error(ArgumentError,'Elements within the permitted array must be hashes with both type and value')
      expect { R509::Cert::Extensions::NameConstraints.new( :permitted => [{'value' => '127'}] ) }.to raise_error(ArgumentError,'Elements within the permitted array must be hashes with both type and value')
    end

    it "raises an error when an invalid type is specified" do
      expect { R509::Cert::Extensions::NameConstraints.new( :permitted => [{:type => 'invalid', :value => '127'}] ) }.to raise_error(ArgumentError,'invalid is not an allowed type. Check R509::ASN1::GeneralName.map_type_to_tag to see a list of types')
    end
  end

  context "NameConstraints" do
    context "creation & yaml generation" do
      context "one permitted" do
        before :all do
          @args = { :permitted => [ { :type => 'DNS', :value => 'domain.com' }], :critical => true }
          @nc = R509::Cert::Extensions::NameConstraints.new(@args)
        end

        it "creates extension" do
          @nc.permitted.names.size.should == 1
          @nc.permitted.names[0].value.should == 'domain.com'
          @nc.permitted.names[0].short_type.should == 'DNS'
        end

        it "builds yaml" do
          YAML.load(@nc.to_yaml).should == @args
        end
      end

      context "creates with multiple permitted" do
        before :all do
          @args = {
            :critical => true,
            :permitted => [
              { :type => 'DNS', :value => 'domain.com' },
              { :type => 'IP', :value => '127.0.0.1/255.255.255.255' },
              { :type => 'dirName', :value => {:CN => 'myCN', :O => 'myO', :C => "US" } }
            ]
          }
          @nc = R509::Cert::Extensions::NameConstraints.new(@args)
        end

        it "creates extension" do
          @nc.permitted.names.size.should == 3
          @nc.permitted.names[0].value.should == 'domain.com'
          @nc.permitted.names[0].short_type.should == 'DNS'
          @nc.permitted.names[1].value.should == '127.0.0.1/255.255.255.255'
          @nc.permitted.names[1].short_type.should == 'IP'
          @nc.permitted.names[2].value.to_s.should == '/CN=myCN/O=myO/C=US'
          @nc.permitted.names[2].short_type.should == 'dirName'
        end

        it "builds yaml" do
          YAML.load(@nc.to_yaml).should == @args
        end
      end

      context "creates with one excluded" do
        before :all do
          @args = { :excluded => [ { :type => 'DNS', :value => 'domain.com' }], :critical => true }
          @nc = R509::Cert::Extensions::NameConstraints.new(@args)
        end

        it "creates extension" do
          @nc.excluded.names.size.should == 1
          @nc.excluded.names[0].value.should == 'domain.com'
          @nc.excluded.names[0].short_type.should == 'DNS'
        end

        it "builds yaml" do
          YAML.load(@nc.to_yaml).should == @args
        end
      end

      context "multiple excluded" do
        before :all do
          @args = {
            :critical => true,
            :excluded => [
              { :type => 'DNS', :value => 'domain.com' },
              { :type => 'IP', :value => '127.0.0.1/255.255.255.255' },
              { :type => 'dirName', :value => {:CN => 'myCN', :O => 'myO', :C => "US" } }
            ]
          }
          @nc = R509::Cert::Extensions::NameConstraints.new(@args)
        end

        it "creates extension" do
          @nc.excluded.names.size.should == 3
          @nc.excluded.names[0].value.should == 'domain.com'
          @nc.excluded.names[0].short_type.should == 'DNS'
          @nc.excluded.names[1].value.should == '127.0.0.1/255.255.255.255'
          @nc.excluded.names[1].short_type.should == 'IP'
          @nc.excluded.names[2].value.to_s.should == '/CN=myCN/O=myO/C=US'
          @nc.excluded.names[2].short_type.should == 'dirName'
        end

        it "builds yaml" do
          YAML.load(@nc.to_yaml).should == @args
        end
      end

      context "both permitted and excluded" do
        before :all do
          @args = {
            :critical => true,
            :excluded => [
              { :type => 'DNS', :value => 'domain.com' },
              { :type => 'IP', :value => '127.0.0.1/255.255.255.255' },
              { :type => 'dirName', :value => {:CN => 'myCN', :O => 'myO', :C => "US" } }
            ],
            :permitted => [
              { :type => 'DNS', :value => 'domain.com' },
              { :type => 'IP', :value => '127.0.0.1/255.255.255.255' },
              { :type => 'dirName', :value => {:CN => 'myCN', :O => 'myO', :C => "US" } }
            ]
          }
          @nc = R509::Cert::Extensions::NameConstraints.new(@args)
        end

        it "creates extension" do
          @nc.permitted.names.size.should == 3
          @nc.permitted.names[0].value.should == 'domain.com'
          @nc.permitted.names[0].short_type.should == 'DNS'
          @nc.permitted.names[1].value.should == '127.0.0.1/255.255.255.255'
          @nc.permitted.names[1].short_type.should == 'IP'
          @nc.permitted.names[2].value.to_s.should == '/CN=myCN/O=myO/C=US'
          @nc.permitted.names[2].short_type.should == 'dirName'
          @nc.excluded.names.size.should == 3
          @nc.excluded.names[0].value.should == 'domain.com'
          @nc.excluded.names[0].short_type.should == 'DNS'
          @nc.excluded.names[1].value.should == '127.0.0.1/255.255.255.255'
          @nc.excluded.names[1].short_type.should == 'IP'
          @nc.excluded.names[2].value.to_s.should == '/CN=myCN/O=myO/C=US'
          @nc.excluded.names[2].short_type.should == 'dirName'
        end

        it "builds yaml" do
          YAML.load(@nc.to_yaml).should == @args
        end
      end

      context "creates with default criticality" do
        before :all do
          @args = { :permitted => [ { :type => 'DNS', :value => 'domain.com' }] }
          @nc = R509::Cert::Extensions::NameConstraints.new(@args)
        end

        it "creates extension" do
          @nc.critical?.should == true
        end

        it "builds yaml" do
          YAML.load(@nc.to_yaml).should == @args.merge(:critical => true)
        end
      end

      context "creates with non-default criticality" do
        before :all do
          @args = { :permitted => [ { :type => 'DNS', :value => 'domain.com' }], :critical => false }
          @nc = R509::Cert::Extensions::NameConstraints.new(@args)
        end

        it "creates extension" do
          @nc.critical?.should == false
        end

        it "builds yaml" do
          YAML.load(@nc.to_yaml).should == @args
        end
      end

    end

    context "with one permitted name" do
      before :all do
        @excluded = []
        @permitted = [{:tag => 2, :value => ".whatever.com"}]
        gns = R509::ASN1::GeneralNames.new
        @permitted.each do |name|
          gns.add_item(name)
        end
        @conf = []
        permitted = gns.names.map do |name|
          serialized = name.serialize_name
          @conf << serialized[:conf]
          "permitted;" + serialized[:extension_string]
        end.join(",")
        @extension_value = permitted
        @conf = @conf.join("\n")
      end

      it_should_behave_like "a correct R509 NameConstraints object", false
      it_should_behave_like "a correct R509 NameConstraints object", true
    end
    context "with multiple permitted names" do
      before :all do
        @excluded = []
        @permitted = [{:tag => 2, :value => ".whatever.com"}, {:tag => 1, :value => "user@emaildomain.com" } ]
        gns = R509::ASN1::GeneralNames.new
        @permitted.each do |name|
          gns.add_item(name)
        end
        @conf = []
        permitted = gns.names.map do |name|
          serialized = name.serialize_name
          @conf << serialized[:conf]
          "permitted;" + serialized[:extension_string]
        end.join(",")
        @extension_value = permitted
        @conf = @conf.join("\n")
      end

      it_should_behave_like "a correct R509 NameConstraints object", false
      it_should_behave_like "a correct R509 NameConstraints object", true
    end
    context "with one excluded name" do
      before :all do
        @permitted = []
        @excluded = [{:tag => 7, :value => "127.0.0.1/255.255.255.255"}]
        egns = R509::ASN1::GeneralNames.new
        @excluded.each do |name|
          egns.add_item(name)
        end
        @conf = []
        excluded = egns.names.map do |name|
          serialized = name.serialize_name
          @conf << serialized[:conf]
          "excluded;" + serialized[:extension_string]
        end.join(",")
        @extension_value = excluded
        @conf = @conf.join("\n")
      end

      it_should_behave_like "a correct R509 NameConstraints object", false
      it_should_behave_like "a correct R509 NameConstraints object", true
    end
    context "with multiple excluded names" do
      before :all do
        @permitted = []
        @excluded = [{:tag => 7, :value => "127.0.0.1/255.255.255.255"}, {:tag => 1, :value => "emaildomain.com" } ]
        @permitted = []
        egns = R509::ASN1::GeneralNames.new
        @excluded.each do |name|
          egns.add_item(name)
        end
        @conf = []
        excluded = egns.names.map do |name|
          serialized = name.serialize_name
          @conf << serialized[:conf]
          "excluded;" + serialized[:extension_string]
        end.join(",")
        @extension_value = excluded
        @conf = @conf.join("\n")
      end

      it_should_behave_like "a correct R509 NameConstraints object", false
      it_should_behave_like "a correct R509 NameConstraints object", true
    end
    context "with both permitted and excluded names" do
      before :all do
        @excluded = [{:tag => 7, :value => "127.0.0.1/255.255.255.255"}, {:tag => 1, :value => "emaildomain.com" } ]
        @permitted = [{:tag => 2, :value => ".whatever.com"}, {:tag => 1, :value => "user@emaildomain.com"} ]
        gns = R509::ASN1::GeneralNames.new
        @permitted.each do |name|
          gns.add_item(name)
        end
        @conf = []
        permitted = gns.names.map do |name|
          serialized = name.serialize_name
          @conf << serialized[:conf]
          "permitted;" + serialized[:extension_string]
        end.join(",")
        egns = R509::ASN1::GeneralNames.new
        @excluded.each do |name|
          egns.add_item(name)
        end
        excluded = egns.names.map do |name|
          serialized = name.serialize_name
          @conf << serialized[:conf]
          "excluded;" + serialized[:extension_string]
        end.join(",")
        @extension_value = permitted + "," + excluded
        @conf = @conf.join("\n")
      end

      it_should_behave_like "a correct R509 NameConstraints object", false
      it_should_behave_like "a correct R509 NameConstraints object", true
    end
  end
end
