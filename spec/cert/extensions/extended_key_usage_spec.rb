require 'spec_helper'

include R509::Cert::Extensions

shared_examples_for "a correct R509 ExtendedKeyUsage object" do |critical|
  before :all do
    extension_name = "extendedKeyUsage"
    klass = ExtendedKeyUsage
    ef = OpenSSL::X509::ExtensionFactory.new
    openssl_ext = ef.create_extension(extension_name, @extension_value, critical)
    @r509_ext = klass.new(openssl_ext)
  end

  it "allowed_uses should be non-nil critical:#{critical}" do
    expect(@r509_ext.allowed_uses).not_to be_nil
  end

  it "allowed_uses should be correct critical:#{critical}" do
    expect(@r509_ext.allowed_uses).to eq(@allowed_uses)
  end

  it "the individual allowed-use functions should be correct critical:#{critical}" do
    expect(@r509_ext.web_server_authentication?).to eq(@allowed_uses.include?(ExtendedKeyUsage::AU_WEB_SERVER_AUTH))
    expect(@r509_ext.web_client_authentication?).to eq(@allowed_uses.include?(ExtendedKeyUsage::AU_WEB_CLIENT_AUTH))
    expect(@r509_ext.code_signing?).to eq(@allowed_uses.include?(ExtendedKeyUsage::AU_CODE_SIGNING))
    expect(@r509_ext.email_protection?).to eq(@allowed_uses.include?(ExtendedKeyUsage::AU_EMAIL_PROTECTION))
    expect(@r509_ext.ocsp_signing?).to eq(@allowed_uses.include?(ExtendedKeyUsage::AU_OCSP_SIGNING))
    expect(@r509_ext.time_stamping?).to eq(@allowed_uses.include?(ExtendedKeyUsage::AU_TIME_STAMPING))
    expect(@r509_ext.any_extended_key_usage?).to eq(@allowed_uses.include?(ExtendedKeyUsage::AU_ANY_EXTENDED_KEY_USAGE))
  end

  it "the #allows? method should work critical:#{critical}" do
    @allowed_uses.each do |au|
      expect(@r509_ext.allows?(au)).to eq(true)
    end
  end

  it "reports #critical? properly" do
    expect(@r509_ext.critical?).to eq(critical)
  end
end

describe R509::Cert::Extensions::ExtendedKeyUsage do
  include R509::Cert::Extensions

  context "validate extended key usage" do
    it "errors with non-array" do
      expect { R509::Cert::Extensions::ExtendedKeyUsage.new('not an array') }.to raise_error(ArgumentError, 'You must pass a hash with a key :value that contains an array of strings (see README)')
    end

    it "errors with nil" do
      expect { R509::Cert::Extensions::ExtendedKeyUsage.new(nil) }.to raise_error(ArgumentError, 'You must pass a hash with a key :value that contains an array of strings (see README)')
    end

    it "errors with hash with no :value" do
      expect { R509::Cert::Extensions::ExtendedKeyUsage.new({}) }.to raise_error(ArgumentError, 'You must pass a hash with a key :value that contains an array of strings (see README)')
    end

    it "errors with hash with non-array :value" do
      expect { R509::Cert::Extensions::KeyUsage.new(:value => "string") }.to raise_error(ArgumentError, 'You must pass a hash with a key :value that contains an array of strings (see README)')
    end
  end

  context "ExtendedKeyUsage" do
    context "creation & yaml generation" do
      context "single EKU" do
        before :all do
          @args = { :value => ['serverAuth'], :critical => false }
          @eku = R509::Cert::Extensions::ExtendedKeyUsage.new(@args)
        end

        it "creates extension" do
          expect(@eku.allowed_uses).to eq(['serverAuth'])
        end

        it "builds yaml" do
          expect(YAML.load(@eku.to_yaml)).to eq(@args)
        end
      end

      context "multiple EKU" do
        before :all do
          @args = { :value => ['serverAuth', 'codeSigning'], :critical => false }
          @eku = R509::Cert::Extensions::ExtendedKeyUsage.new(@args)
        end

        it "creates extension" do
          expect(@eku.allowed_uses).to eq(['serverAuth', 'codeSigning'])
        end

        it "builds yaml" do
          expect(YAML.load(@eku.to_yaml)).to eq(@args)
        end
      end

      context "default criticality" do
        before :all do
          @args = { :value => ['serverAuth'] }
          @eku = R509::Cert::Extensions::ExtendedKeyUsage.new(@args)
        end

        it "creates extension" do
          expect(@eku.critical?).to be false
        end

        it "builds yaml" do
          expect(YAML.load(@eku.to_yaml)).to eq(@args.merge(:critical => false))
        end
      end

      context "non-default criticality" do
        before :all do
          @args = { :value => ['serverAuth'], :critical => true }
          @eku = R509::Cert::Extensions::ExtendedKeyUsage.new(@args)
        end

        it "creates extension" do
          expect(@eku.critical?).to be true
        end

        it "builds yaml" do
          expect(YAML.load(@eku.to_yaml)).to eq(@args)
        end
      end

    end

    context "with one allowed use" do
      before :all do
        @allowed_uses = [ExtendedKeyUsage::AU_WEB_SERVER_AUTH]
        @extension_value = @allowed_uses.join(", ")
      end

      it_should_behave_like "a correct R509 ExtendedKeyUsage object", false
      it_should_behave_like "a correct R509 ExtendedKeyUsage object", true
    end

    context "with some allowed uses" do
      before :all do
        # this spec and the one below alternate the uses
        @allowed_uses = [ExtendedKeyUsage::AU_WEB_SERVER_AUTH, ExtendedKeyUsage::AU_CODE_SIGNING]
        @extension_value = @allowed_uses.join(", ")
      end

      it_should_behave_like "a correct R509 ExtendedKeyUsage object", false
      it_should_behave_like "a correct R509 ExtendedKeyUsage object", true
    end

    context "with some different allowed uses" do
      before :all do
        @allowed_uses = [ExtendedKeyUsage::AU_WEB_CLIENT_AUTH, ExtendedKeyUsage::AU_EMAIL_PROTECTION]
        @extension_value = @allowed_uses.join(", ")
      end

      it_should_behave_like "a correct R509 ExtendedKeyUsage object", false
      it_should_behave_like "a correct R509 ExtendedKeyUsage object", true
    end

    context "with all allowed uses" do
      before :all do
        @allowed_uses = [
          ExtendedKeyUsage::AU_WEB_SERVER_AUTH,
          ExtendedKeyUsage::AU_CODE_SIGNING,
          ExtendedKeyUsage::AU_WEB_CLIENT_AUTH,
          ExtendedKeyUsage::AU_EMAIL_PROTECTION,
          ExtendedKeyUsage::AU_TIME_STAMPING,
          ExtendedKeyUsage::AU_OCSP_SIGNING,
          ExtendedKeyUsage::AU_ANY_EXTENDED_KEY_USAGE
        ]
        @extension_value = @allowed_uses.join(", ")
      end

      it_should_behave_like "a correct R509 ExtendedKeyUsage object", false
      it_should_behave_like "a correct R509 ExtendedKeyUsage object", true
    end
  end

end
