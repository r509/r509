require 'spec_helper'

include R509::Cert::Extensions

shared_examples_for "a correct R509 InhibitAnyPolicy object" do |critical|
  before :all do
    extension_name = "inhibitAnyPolicy"
    klass = InhibitAnyPolicy
    ef = OpenSSL::X509::ExtensionFactory.new
    openssl_ext = ef.create_extension(extension_name, @value.to_s, critical)
    @r509_ext = klass.new(openssl_ext)
  end

  it "should parse the integer value out of the extension" do
    expect(@r509_ext.value).to eq(@value)
  end

  it "reports #critical? properly" do
    expect(@r509_ext.critical?).to eq(critical)
  end
end

describe R509::Cert::Extensions::InhibitAnyPolicy do
  include R509::Cert::Extensions

  context "validate inhibit any policy" do
    it "raises an error when not a number" do
      expect { R509::Cert::Extensions::InhibitAnyPolicy.new(:value => "string") }.to raise_error(ArgumentError, 'Inhibit any policy must be a non-negative integer')
    end
    it "raises an error when not >= 0" do
      expect { R509::Cert::Extensions::InhibitAnyPolicy.new(:value => -5) }.to raise_error(ArgumentError, 'Inhibit any policy must be a non-negative integer')
    end
  end

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
          expect(@iap.value).to eq(1)
        end

        it "builds yaml" do
          expect(YAML.load(@iap.to_yaml)).to eq(@args)
        end
      end

      context "creates with default criticality" do
        before :all do
          @args = { :value => 1 }
          @iap = R509::Cert::Extensions::InhibitAnyPolicy.new(@args)
        end

        it "creates extension" do
          expect(@iap.critical?).to eq(true)
        end

        it "builds yaml" do
          expect(YAML.load(@iap.to_yaml)).to eq(@args.merge(:critical => true))
        end
      end

      context "creates with non-default criticality" do
        before :all do
          @args = { :value => 1, :critical => false }
          @iap = R509::Cert::Extensions::InhibitAnyPolicy.new(@args)
        end

        it "creates extension" do
          expect(@iap.critical?).to eq(false)
        end

        it "builds yaml" do
          expect(YAML.load(@iap.to_yaml)).to eq(@args)
        end
      end

    end

    it_should_behave_like "a correct R509 InhibitAnyPolicy object", false
    it_should_behave_like "a correct R509 InhibitAnyPolicy object", true
  end

end
