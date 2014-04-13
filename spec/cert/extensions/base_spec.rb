require 'spec_helper'

include R509::Cert::Extensions

shared_examples_for "a correctly implemented wrap_openssl_extensions" do
  before :each do
    @r509_extensions = R509::Cert::Extensions.wrap_openssl_extensions(@openssl_extensions)

    @r509_classes = [
      BasicConstraints, KeyUsage, ExtendedKeyUsage,
      SubjectKeyIdentifier, AuthorityKeyIdentifier,
      SubjectAlternativeName, AuthorityInfoAccess,
      CRLDistributionPoints, OCSPNoCheck
    ]
  end

  it "should not have returned values that aren't R509 extensions" do
    classes = @r509_extensions.values.map { |ext| ext.class }
    non_r509_classes = classes.reject { |ext_class| @r509_classes.include?(ext_class) }
    non_r509_classes.should == []
  end

  it "should have returned the right number of extensions" do
    @r509_extensions.count.should == @wrappable_extensions.count
  end

  it "should not have returned keys improperly mapped to values" do
    incorrect_mappings = @r509_extensions.select { |key_class, ext| ext.class != key_class }
    incorrect_mappings = {} if incorrect_mappings == [] # compatibility for old versions of Ruby
    incorrect_mappings.should == {}
  end

  it "should not have failed to map an implemented extension" do
    missing_extensions = []
    @wrappable_extensions.each do |openssl_ext|
      if (@r509_extensions.select { |r509_class, r509_ext| r509_ext.oid == openssl_ext.oid }) == {}
        missing_extensions << openssl_ext.oid
      end
    end

    missing_extensions.should == []
  end
end

shared_examples_for "a correctly implemented get_unknown_extensions" do
  it "should not have returned values that are R509 extensions" do
    R509::Cert::Extensions.get_unknown_extensions(@openssl_extensions).should == @unknown_extensions
  end
end

describe R509::Cert::Extensions do
  include R509::Cert::Extensions

  context "Class functions" do
    context "#wrap_openssl_extensions and #get_unknown_extensions" do
      context "with no extensions" do
        before :each do
          @wrappable_extensions = []
          @unknown_extensions = []

          @openssl_extensions = @wrappable_extensions + @unknown_extensions
        end

        it_should_behave_like "a correctly implemented wrap_openssl_extensions"
        it_should_behave_like "a correctly implemented get_unknown_extensions"
      end

      context "with one implemented extension" do
        before :each do
          @wrappable_extensions = []
          ef = OpenSSL::X509::ExtensionFactory.new
          @wrappable_extensions << ef.create_extension("basicConstraints", "CA:TRUE,pathlen:0")

          @unknown_extensions = []

          @openssl_extensions = @wrappable_extensions + @unknown_extensions
        end

        it_should_behave_like "a correctly implemented wrap_openssl_extensions"
        it_should_behave_like "a correctly implemented get_unknown_extensions"
      end

      context "with all implemented extensions" do
        before :each do
          @wrappable_extensions = []
          ef = OpenSSL::X509::ExtensionFactory.new
          ef.issuer_certificate = OpenSSL::X509::Certificate.new TestFixtures::TEST_CA_CERT
          ef.subject_certificate = OpenSSL::X509::Certificate.new TestFixtures::TEST_CA_CERT
          @wrappable_extensions << ef.create_extension("basicConstraints", "CA:TRUE,pathlen:0", true)
          @wrappable_extensions << ef.create_extension("keyUsage", KeyUsage::AU_DIGITAL_SIGNATURE)
          @wrappable_extensions << ef.create_extension("extendedKeyUsage", ExtendedKeyUsage::AU_WEB_SERVER_AUTH)
          @wrappable_extensions << ef.create_extension("subjectKeyIdentifier", "hash")
          @wrappable_extensions << ef.create_extension("authorityKeyIdentifier", "keyid:always")
          @wrappable_extensions << ef.create_extension("subjectAltName", "DNS:www.test.local")
          @wrappable_extensions << ef.create_extension("authorityInfoAccess", "caIssuers;URI:http://www.test.local")
          @wrappable_extensions << ef.create_extension("crlDistributionPoints", "URI:http://www.test.local")

          @unknown_extensions = []

          @openssl_extensions = @wrappable_extensions + @unknown_extensions
        end

        it_should_behave_like "a correctly implemented wrap_openssl_extensions"
        it_should_behave_like "a correctly implemented get_unknown_extensions"
      end

      context "with an unimplemented extension" do
        before :each do
          @wrappable_extensions = []

          @unknown_extensions = []
          @unknown_extensions << OpenSSL::X509::Extension.new("issuerAltName", "DNS:www.test.local")

          @openssl_extensions = @wrappable_extensions + @unknown_extensions
        end

        it_should_behave_like "a correctly implemented wrap_openssl_extensions"
        it_should_behave_like "a correctly implemented get_unknown_extensions"
      end

      context "with implemented and unimplemented extensions" do
        before :each do
          @wrappable_extensions = []
          ef = OpenSSL::X509::ExtensionFactory.new
          @wrappable_extensions << ef.create_extension("basicConstraints", "CA:TRUE,pathlen:0")

          @unknown_extensions = []
          @unknown_extensions << OpenSSL::X509::Extension.new("issuerAltName", "DNS:www.test.local")

          @openssl_extensions = @wrappable_extensions + @unknown_extensions
        end

        it_should_behave_like "a correctly implemented wrap_openssl_extensions"
        it_should_behave_like "a correctly implemented get_unknown_extensions"
      end

      context "with multiple extensions of an implemented type" do
        before :each do
          @wrappable_extensions = []
          ef = OpenSSL::X509::ExtensionFactory.new
          @wrappable_extensions << ef.create_extension("basicConstraints", "CA:TRUE,pathlen:0")
          @wrappable_extensions << ef.create_extension("basicConstraints", "CA:TRUE,pathlen:1")

          @unknown_extensions = []
          @unknown_extensions << OpenSSL::X509::Extension.new("issuerAltName", "DNS:www.test.local")

          @openssl_extensions = @wrappable_extensions + @unknown_extensions
        end

        it "should raise an ArgumentError for #wrap_openssl_extensions" do
          expect do
            R509::Cert::Extensions.wrap_openssl_extensions(@openssl_extensions)
          end.to raise_error(ArgumentError)
        end
        it_should_behave_like "a correctly implemented get_unknown_extensions"
      end

      context "with multiple extensions of an unimplemented type" do
        before :each do
          @wrappable_extensions = []
          ef = OpenSSL::X509::ExtensionFactory.new
          @wrappable_extensions << ef.create_extension("basicConstraints", "CA:TRUE,pathlen:0")

          @unknown_extensions = []
          @unknown_extensions << OpenSSL::X509::Extension.new("issuerAltName", "DNS:www.test.local")
          @unknown_extensions << OpenSSL::X509::Extension.new("issuerAltName", "DNS:www2.test.local")

          @openssl_extensions = @wrappable_extensions + @unknown_extensions
        end

        it_should_behave_like "a correctly implemented wrap_openssl_extensions"
        it_should_behave_like "a correctly implemented get_unknown_extensions"
      end
    end
  end
end
