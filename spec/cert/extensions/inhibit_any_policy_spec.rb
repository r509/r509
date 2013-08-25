require 'spec_helper'

include R509::Cert::Extensions

shared_examples_for "a correct R509 InhibitAnyPolicy object" do |critical|
  before :all do
    extension_name = "inhibitAnyPolicy"
    klass = InhibitAnyPolicy
    ef = OpenSSL::X509::ExtensionFactory.new
    openssl_ext = ef.create_extension( extension_name, @value.to_s,critical)
    @r509_ext = klass.new( openssl_ext )
  end

  it "should parse the integer value out of the extension" do
    @r509_ext.value.should == @value
  end

  it "reports #critical? properly" do
    @r509_ext.critical?.should == critical
  end
end

describe R509::Cert::Extensions do
  include R509::Cert::Extensions

  context "InhibitAnyPolicy" do
    before :all do
      @value = 3
    end

    context "creation & yaml generation" do
      context "creates with a positive skip #" do
        before :all do
          @args = { :value => 1, :critical => true }
          @iap = R509::Cert::Extensions::InhibitAnyPolicy.new(@args)
        end

        it "creates extension" do
          @iap.value.should == 1
        end

        it "builds yaml" do
          YAML.load(@iap.to_yaml).should == @args
        end
      end

      context "creates with default criticality" do
        before :all do
          @args = { :value => 1 }
          @iap = R509::Cert::Extensions::InhibitAnyPolicy.new(@args)
        end

        it "creates extension" do
          @iap.critical?.should == true
        end

        it "builds yaml" do
          YAML.load(@iap.to_yaml).should == @args.merge(:critical => true)
        end
      end

      context "creates with non-default criticality" do
        before :all do
          @args = { :value => 1, :critical => false }
          @iap = R509::Cert::Extensions::InhibitAnyPolicy.new(@args)
        end

        it "creates extension" do
          @iap.critical?.should == false
        end

        it "builds yaml" do
          YAML.load(@iap.to_yaml).should == @args
        end
      end

    end

    it_should_behave_like "a correct R509 InhibitAnyPolicy object", false
    it_should_behave_like "a correct R509 InhibitAnyPolicy object", true
  end

end
