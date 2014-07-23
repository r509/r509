require 'spec_helper'

include R509::Cert::Extensions

shared_examples_for "a correct R509 SubjectKeyIdentifier object" do
  before :all do
    extension_name = "subjectKeyIdentifier"
    klass = SubjectKeyIdentifier
    openssl_ext = OpenSSL::X509::Extension.new(extension_name, @extension_value)
    @r509_ext = klass.new(openssl_ext)
  end

  it "key should be correct" do
    expect(@r509_ext.key).to eq(@key)
  end
end

describe R509::Cert::Extensions::SubjectKeyIdentifier do
  include R509::Cert::Extensions

  context "SubjectKeyIdentifier" do
    before :all do
      @extension_value = "00:11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF:00:11:22"
      @key = @extension_value
    end

    context "creation" do
      before :all do
        @pk = R509::PrivateKey.new(:bit_strength => 768)
      end

      it "errors when not supplying a public key" do
        expect do
          R509::Cert::Extensions::SubjectKeyIdentifier.new({})
        end.to raise_error(ArgumentError, "You must supply a hash with a :public_key")
      end

      it "errors when supplying a non-hash" do
        expect do
          R509::Cert::Extensions::SubjectKeyIdentifier.new("junk!!!")
        end.to raise_error(ArgumentError, "You must supply a hash with a :public_key")
      end

      it "creates successfully" do
        ski = R509::Cert::Extensions::SubjectKeyIdentifier.new(:public_key => @pk.public_key)
        expect(ski.key).not_to be_nil
      end

      it "creates with default criticality" do
        ski = R509::Cert::Extensions::SubjectKeyIdentifier.new(:public_key => @pk.public_key)
        expect(ski.critical?).to be false
      end

      it "creates with non-default criticality" do
        ski = R509::Cert::Extensions::SubjectKeyIdentifier.new(:public_key => @pk.public_key, :critical => true)
        expect(ski.critical?).to be true
      end

    end

    it_should_behave_like "a correct R509 SubjectKeyIdentifier object"
  end

end
