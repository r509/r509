require 'spec_helper'

include R509::Cert::Extensions

shared_examples_for "a correct R509 AuthorityKeyIdentifier object" do
  before :all do
    extension_name = "authorityKeyIdentifier"
    klass = AuthorityKeyIdentifier
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.issuer_certificate = OpenSSL::X509::Certificate.new TestFixtures::TEST_CA_CERT
    openssl_ext = ef.create_extension(extension_name, @extension_value)
    @r509_ext = klass.new(openssl_ext)
  end

  it "has the expected type" do
    @r509_ext.oid.should == "authorityKeyIdentifier"
  end

  it "contains the key identifier" do
    @r509_ext.key_identifier.should == "79:75:BB:84:3A:CB:2C:DE:7A:09:BE:31:1B:43:BC:1C:2A:4D:53:58"
  end
  it "parses the authority cert issuer and serial number" do
    @r509_ext.authority_cert_issuer.value.to_s.should == "/C=US/ST=Illinois/L=Chicago/O=Ruby CA Project/CN=Test CA"
    @r509_ext.authority_cert_serial_number.should == 'FF:D9:C7:0B:87:37:D1:94'
  end
end

describe R509::Cert::Extensions::AuthorityKeyIdentifier do
  include R509::Cert::Extensions

  context "creation" do
    before :all do
      @cert = TestFixtures.test_ca_cert
    end

    it "errors when not supplying a public_key" do
      expect do
        R509::Cert::Extensions::AuthorityKeyIdentifier.new({})
      end.to raise_error(ArgumentError,'You must supply an OpenSSL::PKey object to :public_key if aki value contains keyid (present by default)')
    end

    it "errors when not supplying an issuer subject when embedding issuer info" do
      expect do
        R509::Cert::Extensions::AuthorityKeyIdentifier.new(:value => "issuer:always", :issuer_serial => 3)
      end.to raise_error(ArgumentError,'You must supply an R509::Subject object to :issuer_subject if aki value contains issuer')
    end

    it "errors when not supplying an issuer serial when embedding issuer info" do
      expect do
        R509::Cert::Extensions::AuthorityKeyIdentifier.new(:value => "issuer:always", :issuer_subject => R509::Subject.new(:CN => 'something'))
      end.to raise_error(ArgumentError,'You must supply an integer to :issuer_serial if aki value contains issuer')
    end

    it "creates successfully with default value" do
      aki = R509::Cert::Extensions::AuthorityKeyIdentifier.new(:public_key => @cert.public_key)
      aki.key_identifier.should_not be_nil
      aki.authority_cert_issuer.should be_nil
    end

    it "creates successfully with issuer value" do
      aki = R509::Cert::Extensions::AuthorityKeyIdentifier.new(:issuer_subject => @cert.subject, :issuer_serial => 5, :value => "issuer:always")
      aki.authority_cert_issuer.to_h.should == { :type=>"dirName", :value=>{ :C=>"US", :ST=>"Illinois", :L=>"Chicago", :O=>"Ruby CA Project", :CN=>"Test CA" } }
      aki.authority_cert_serial_number.should == "05"
    end

    it "creates successfully with issuer+keyid value" do
      aki = R509::Cert::Extensions::AuthorityKeyIdentifier.new(:issuer_subject => @cert.subject, :issuer_serial => 5, :public_key => @cert.public_key, :value => "issuer:always,keyid:always")
      aki.authority_cert_issuer.to_h.should == { :type=>"dirName", :value=>{ :C=>"US", :ST=>"Illinois", :L=>"Chicago", :O=>"Ruby CA Project", :CN=>"Test CA" } }
      aki.authority_cert_serial_number.should_not be_nil
      aki.key_identifier.should_not be_nil
    end

    it "creates with default criticality" do
      aki = R509::Cert::Extensions::AuthorityKeyIdentifier.new(:public_key => @cert.public_key)
      aki.critical?.should be_false
    end

    it "creates with non-default criticality" do
      aki = R509::Cert::Extensions::AuthorityKeyIdentifier.new(:public_key => @cert.public_key, :critical => true)
      aki.critical?.should be_true
    end

  end
  context "AuthorityKeyIdentifier" do
    before :all do
      @extension_value = "keyid:always,issuer:always"
    end

    it_should_behave_like "a correct R509 AuthorityKeyIdentifier object"
  end
end
