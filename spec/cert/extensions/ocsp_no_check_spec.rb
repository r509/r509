require 'spec_helper'

include R509::Cert::Extensions

shared_examples_for "a correct R509 OCSPNoCheck object" do |critical|
  before :all do
    extension_name = "noCheck"
    klass = OCSPNoCheck
    ef = OpenSSL::X509::ExtensionFactory.new
    openssl_ext = ef.create_extension(extension_name, "irrelevant", critical)
    @r509_ext = klass.new(openssl_ext)
  end

  it "has the expected type" do
    expect(@r509_ext.oid).to eq("noCheck")
  end

  it "reports #critical? properly" do
    expect(@r509_ext.critical?).to eq(critical)
  end
end

describe R509::Cert::Extensions::OCSPNoCheck do
  include R509::Cert::Extensions

  context "OCSPNoCheck" do
    context "creation & yaml generation" do
      context "when passed a hash" do
        before :all do
          @no_check = R509::Cert::Extensions::OCSPNoCheck.new({})
        end

        it "creates extension" do
          expect(@no_check).not_to be_nil
        end

        it "builds yaml" do
          expect(YAML.load(@no_check.to_yaml)).to eq(:critical => false)
        end
      end

      context "default criticality" do
        before :all do
          @no_check = R509::Cert::Extensions::OCSPNoCheck.new({})
        end

        it "creates extension" do
          expect(@no_check.critical?).to be false
        end

        it "builds yaml" do
          expect(YAML.load(@no_check.to_yaml)).to eq(:critical => false)
        end
      end

      context "non-default criticality" do
        before :all do
          @no_check = R509::Cert::Extensions::OCSPNoCheck.new(:critical => true)
        end

        it "creates extension" do
          expect(@no_check.critical?).to be true
        end

        it "builds yaml" do
          expect(YAML.load(@no_check.to_yaml)).to eq(:critical => true)
        end
      end

    end

    it_should_behave_like "a correct R509 OCSPNoCheck object", false
    it_should_behave_like "a correct R509 OCSPNoCheck object", true
  end

end
