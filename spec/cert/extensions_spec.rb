require 'spec_helper'

include R509::Cert::Extensions

shared_examples_for "a correctly implemented wrap_openssl_extensions" do
  before :each do
    @r509_extensions = R509::Cert::Extensions.wrap_openssl_extensions( @openssl_extensions )

    @r509_classes = [ BasicConstraints, KeyUsage, ExtendedKeyUsage,
            SubjectKeyIdentifier, AuthorityKeyIdentifier,
            SubjectAlternativeName, AuthorityInfoAccess,
            CRLDistributionPoints, OCSPNoCheck ]
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
    incorrect_mappings = @r509_extensions.select { |key_class,ext| ext.class != key_class }
    incorrect_mappings = {} if incorrect_mappings == [] # compatibility for old versions of Ruby
    incorrect_mappings.should == {}
  end

  it "should not have failed to map an implemented extension" do
    missing_extensions = []
    @wrappable_extensions.each do |openssl_ext|
      if (@r509_extensions.select {|r509_class,r509_ext| r509_ext.oid == openssl_ext.oid}) == {}
        missing_extensions << openssl_ext.oid
      end
    end

    missing_extensions.should == []
  end
end

shared_examples_for "a correctly implemented get_unknown_extensions" do
  it "should not have returned values that are R509 extensions" do
    R509::Cert::Extensions.get_unknown_extensions( @openssl_extensions ).should == @unknown_extensions
  end
end

shared_examples_for "a correct R509 BasicConstraints object" do |critical|
  before :all do
    extension_name = "basicConstraints"
    klass = BasicConstraints
    ef = OpenSSL::X509::ExtensionFactory.new
    openssl_ext = ef.create_extension( extension_name, @extension_value , critical)
    @r509_ext = klass.new( openssl_ext )
  end

  it "is_ca? should correctly report whether it's a CA certificate (critical:#{critical})" do
    @r509_ext.is_ca?.should == @is_ca
  end

  it "the path length should be correct (critical:#{critical})" do
    @r509_ext.path_length.should == @pathlen
  end

  it "allows_sub_ca? should correctly report whether its path length allows it to issue CA certs (critical:#{critical})" do
    @r509_ext.allows_sub_ca?.should == @allows_sub_ca
  end

  it "reports #critical? properly" do
    @r509_ext.critical?.should == critical
  end
end

shared_examples_for "a correct R509 KeyUsage object" do |critical|
  before :each do
    extension_name = "keyUsage"
    klass = KeyUsage
    ef = OpenSSL::X509::ExtensionFactory.new
    openssl_ext = ef.create_extension( extension_name, @extension_value, critical )
    @r509_ext = klass.new( openssl_ext )
  end

  it "allowed_uses should be non-nil critical:#{critical}" do
    @r509_ext.allowed_uses.should_not == nil
  end

  it "allowed_uses should be correct critical:#{critical}" do
    @r509_ext.allowed_uses.should == @allowed_uses
  end

  it "the individual allowed-use functions should be correct critical:#{critical}" do
    @r509_ext.digital_signature?.should == @allowed_uses.include?( KeyUsage::AU_DIGITAL_SIGNATURE )
    @r509_ext.non_repudiation?.should == @allowed_uses.include?( KeyUsage::AU_NON_REPUDIATION )
    @r509_ext.key_encipherment?.should == @allowed_uses.include?( KeyUsage::AU_KEY_ENCIPHERMENT )
    @r509_ext.data_encipherment?.should == @allowed_uses.include?( KeyUsage::AU_DATA_ENCIPHERMENT )
    @r509_ext.key_agreement?.should == @allowed_uses.include?( KeyUsage::AU_KEY_AGREEMENT )
    @r509_ext.key_cert_sign?.should == @allowed_uses.include?( KeyUsage::AU_KEY_CERT_SIGN )
    @r509_ext.crl_sign?.should == @allowed_uses.include?( KeyUsage::AU_CRL_SIGN )
    @r509_ext.encipher_only?.should == @allowed_uses.include?( KeyUsage::AU_ENCIPHER_ONLY )
    @r509_ext.decipher_only?.should == @allowed_uses.include?( KeyUsage::AU_DECIPHER_ONLY )
  end

  it "the #allows? method should work critical:#{critical}" do
    @allowed_uses.each do |au|
      @r509_ext.allows?(au).should == true
    end
  end

  it "reports #critical? properly" do
    @r509_ext.critical?.should == critical
  end
end

shared_examples_for "a correct R509 ExtendedKeyUsage object" do |critical|
  before :all do
    extension_name = "extendedKeyUsage"
    klass = ExtendedKeyUsage
    ef = OpenSSL::X509::ExtensionFactory.new
    openssl_ext = ef.create_extension( extension_name, @extension_value , critical )
    @r509_ext = klass.new( openssl_ext )
  end

  it "allowed_uses should be non-nil critical:#{critical}" do
    @r509_ext.allowed_uses.should_not == nil
  end

  it "allowed_uses should be correct critical:#{critical}" do
    @r509_ext.allowed_uses.should == @allowed_uses
  end

  it "the individual allowed-use functions should be correct critical:#{critical}" do
    @r509_ext.web_server_authentication?.should == @allowed_uses.include?( ExtendedKeyUsage::AU_WEB_SERVER_AUTH )
    @r509_ext.web_client_authentication?.should == @allowed_uses.include?( ExtendedKeyUsage::AU_WEB_CLIENT_AUTH )
    @r509_ext.code_signing?.should == @allowed_uses.include?( ExtendedKeyUsage::AU_CODE_SIGNING )
    @r509_ext.email_protection?.should == @allowed_uses.include?( ExtendedKeyUsage::AU_EMAIL_PROTECTION )
    @r509_ext.ocsp_signing?.should == @allowed_uses.include?( ExtendedKeyUsage::AU_OCSP_SIGNING )
    @r509_ext.time_stamping?.should == @allowed_uses.include?( ExtendedKeyUsage::AU_TIME_STAMPING )
    @r509_ext.any_extended_key_usage?.should == @allowed_uses.include?( ExtendedKeyUsage::AU_ANY_EXTENDED_KEY_USAGE )
  end

  it "the #allows? method should work critical:#{critical}" do
    @allowed_uses.each do |au|
      @r509_ext.allows?(au).should == true
    end
  end

  it "reports #critical? properly" do
    @r509_ext.critical?.should == critical
  end
end

shared_examples_for "a correct R509 SubjectKeyIdentifier object" do
  before :all do
    extension_name = "subjectKeyIdentifier"
    klass = SubjectKeyIdentifier
    openssl_ext = OpenSSL::X509::Extension.new( extension_name, @extension_value )
    @r509_ext = klass.new( openssl_ext )
  end

  it "key should be correct" do
    @r509_ext.key.should == @key
  end
end

shared_examples_for "a correct R509 AuthorityKeyIdentifier object" do
  before :all do
    extension_name = "authorityKeyIdentifier"
    klass = AuthorityKeyIdentifier
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.issuer_certificate = OpenSSL::X509::Certificate.new TestFixtures::TEST_CA_CERT
    openssl_ext = ef.create_extension( "authorityKeyIdentifier", @extension_value )
    @r509_ext = klass.new( openssl_ext )
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

shared_examples_for "a correct R509 SubjectAlternativeName object" do |critical|
  before :all do
    extension_name = "subjectAltName"
    klass = SubjectAlternativeName
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.config = OpenSSL::Config.parse(@conf)
    openssl_ext = ef.create_extension( extension_name, @extension_value , critical )
    @r509_ext = klass.new( openssl_ext )
  end

  it "dns_names should be correct critical:#{critical}" do
    @r509_ext.dns_names.should == @dns_names
  end

  it "ip_addresses should be correct critical:#{critical}" do
    @r509_ext.ip_addresses.should == @ip_addresses
  end

  it "rfc_822names should be correct critical:#{critical}" do
    @r509_ext.rfc_822_names.should == @rfc_822_names
  end

  it "uris should be correct critical:#{critical}" do
    @r509_ext.uris.should == @uris
  end

  it "dirNames should be correct critical:#{critical}" do
    @r509_ext.directory_names.size.should == @directory_names.size
  end

  it "ordered should be correct critical:#{critical}" do
    @r509_ext.names.size.should == @dns_names.size + @ip_addresses.size + @rfc_822_names.size + @uris.size + @directory_names.size
  end

  it "reports #critical? properly" do
    @r509_ext.critical?.should == critical
  end
end

shared_examples_for "a correct R509 AuthorityInfoAccess object" do |critical|
  before :all do
    extension_name = "authorityInfoAccess"
    klass = AuthorityInfoAccess
    ef = OpenSSL::X509::ExtensionFactory.new
    openssl_ext = ef.create_extension( extension_name, @extension_value, critical )
    @r509_ext = klass.new( openssl_ext )
  end

  it "ca_issuers_uri should be correct critical:#{critical}" do
    @r509_ext.ca_issuers.uris.should == @ca_issuers_uris
  end

  it "ocsp_uri should be correct critical:#{critical}" do
    @r509_ext.ocsp.uris.should == @ocsp_uris
  end

  it "reports #critical? properly" do
    @r509_ext.critical?.should == critical
  end
end

shared_examples_for "a correct R509 CRLDistributionPoints object" do |critical|
  before :all do
    extension_name = "crlDistributionPoints"
    klass = CRLDistributionPoints
    ef = OpenSSL::X509::ExtensionFactory.new
    openssl_ext = ef.create_extension( extension_name, @extension_value , critical )
    @r509_ext = klass.new( openssl_ext )
  end

  it "crl_uri should be correct critical:#{critical}" do
    @r509_ext.crl.uris.should == @crl_uris
  end

  it "reports #critical? properly" do
    @r509_ext.critical?.should == critical
  end
end

shared_examples_for "a correct R509 OCSPNoCheck object" do |critical|
  before :all do
    extension_name = "noCheck"
    klass = OCSPNoCheck
    ef = OpenSSL::X509::ExtensionFactory.new
    openssl_ext = ef.create_extension( extension_name, "irrelevant", critical)
    @r509_ext = klass.new( openssl_ext )
  end

  it "has the expected type" do
    @r509_ext.oid.should == "noCheck"
  end

  it "reports #critical? properly" do
    @r509_ext.critical?.should == critical
  end
end

shared_examples_for "a correct R509 CertificatePolicies object" do
  before :all do
    klass = CertificatePolicies
    openssl_ext = OpenSSL::X509::Extension.new @policy_data
    @r509_ext = klass.new( openssl_ext )
  end

  it "should correctly parse the data" do
    @r509_ext.policies.count.should == 1
    @r509_ext.policies[0].policy_identifier.should == "2.16.840.1.12345.1.2.3.4.1"
    @r509_ext.policies[0].policy_qualifiers.cps_uris.should == ["http://example.com/cps", "http://other.com/cps"]
  end
end

shared_examples_for "a correct R509 InhibitAnyPolicy object" do |critical|
  before :all do
    extension_name = "inhibitAnyPolicy"
    klass = InhibitAnyPolicy
    ef = OpenSSL::X509::ExtensionFactory.new
    openssl_ext = ef.create_extension( extension_name, @skip_certs.to_s,critical)
    @r509_ext = klass.new( openssl_ext )
  end

  it "should parse the integer value out of the extension" do
    @r509_ext.skip_certs.should == @skip_certs
  end

  it "reports #critical? properly" do
    @r509_ext.critical?.should == critical
  end
end

shared_examples_for "a correct R509 PolicyConstraints object" do |critical|
  before :all do
    extension_name = "policyConstraints"
    klass = PolicyConstraints
    ef = OpenSSL::X509::ExtensionFactory.new
    openssl_ext = ef.create_extension( extension_name, @extension_value, critical)
    @r509_ext = klass.new( openssl_ext )
  end

  it "should have the expected require policy" do
    @r509_ext.require_explicit_policy.should == @require_explicit_policy
  end
  it "should have the expected inhibit mapping" do
    @r509_ext.inhibit_policy_mapping.should == @inhibit_policy_mapping
  end
end

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
      @r509_ext.permitted[index].tag.should == name[:tag]
      @r509_ext.permitted[index].value.should == name[:value]
    end
  end
  it "should have the excluded names" do
    @excluded.each_with_index do |name,index|
      @r509_ext.excluded[index].tag.should == name[:tag]
      @r509_ext.excluded[index].value.should == name[:value]
    end
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
          @wrappable_extensions << ef.create_extension( "basicConstraints", "CA:TRUE,pathlen:0" )

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
          @wrappable_extensions << ef.create_extension( "basicConstraints", "CA:TRUE,pathlen:0", true )
          @wrappable_extensions << ef.create_extension( "keyUsage", KeyUsage::AU_DIGITAL_SIGNATURE )
          @wrappable_extensions << ef.create_extension( "extendedKeyUsage", ExtendedKeyUsage::AU_WEB_SERVER_AUTH )
          @wrappable_extensions << ef.create_extension( "subjectKeyIdentifier", "hash" )
          @wrappable_extensions << ef.create_extension( "authorityKeyIdentifier", "keyid:always" )
          @wrappable_extensions << ef.create_extension( "subjectAltName", "DNS:www.test.local" )
          @wrappable_extensions << ef.create_extension( "authorityInfoAccess", "caIssuers;URI:http://www.test.local" )
          @wrappable_extensions << ef.create_extension( "crlDistributionPoints", "URI:http://www.test.local" )

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
          @unknown_extensions << OpenSSL::X509::Extension.new( "issuerAltName", "DNS:www.test.local" )

          @openssl_extensions = @wrappable_extensions + @unknown_extensions
        end

        it_should_behave_like "a correctly implemented wrap_openssl_extensions"
        it_should_behave_like "a correctly implemented get_unknown_extensions"
      end

      context "with implemented and unimplemented extensions" do
        before :each do
          @wrappable_extensions = []
          ef = OpenSSL::X509::ExtensionFactory.new
          @wrappable_extensions << ef.create_extension( "basicConstraints", "CA:TRUE,pathlen:0" )

          @unknown_extensions = []
          @unknown_extensions << OpenSSL::X509::Extension.new( "issuerAltName", "DNS:www.test.local" )

          @openssl_extensions = @wrappable_extensions + @unknown_extensions
        end

        it_should_behave_like "a correctly implemented wrap_openssl_extensions"
        it_should_behave_like "a correctly implemented get_unknown_extensions"
      end

      context "with multiple extensions of an implemented type" do
        before :each do
          @wrappable_extensions = []
          ef = OpenSSL::X509::ExtensionFactory.new
          @wrappable_extensions << ef.create_extension( "basicConstraints", "CA:TRUE,pathlen:0" )
          @wrappable_extensions << ef.create_extension( "basicConstraints", "CA:TRUE,pathlen:1" )

          @unknown_extensions = []
          @unknown_extensions << OpenSSL::X509::Extension.new( "issuerAltName", "DNS:www.test.local" )

          @openssl_extensions = @wrappable_extensions + @unknown_extensions
        end

        it "should raise an ArgumentError for #wrap_openssl_extensions" do
          expect {
            R509::Cert::Extensions.wrap_openssl_extensions( @openssl_extensions )
          }.to raise_error(ArgumentError)
        end
        it_should_behave_like "a correctly implemented get_unknown_extensions"
      end

      context "with multiple extensions of an unimplemented type" do
        before :each do
          @wrappable_extensions = []
          ef = OpenSSL::X509::ExtensionFactory.new
          @wrappable_extensions << ef.create_extension( "basicConstraints", "CA:TRUE,pathlen:0" )

          @unknown_extensions = []
          @unknown_extensions << OpenSSL::X509::Extension.new( "issuerAltName", "DNS:www.test.local" )
          @unknown_extensions << OpenSSL::X509::Extension.new( "issuerAltName", "DNS:www2.test.local" )

          @openssl_extensions = @wrappable_extensions + @unknown_extensions
        end

        it_should_behave_like "a correctly implemented wrap_openssl_extensions"
        it_should_behave_like "a correctly implemented get_unknown_extensions"
      end
    end
  end

  context "BasicConstraints" do
    context "creation" do
      it "creates CA:TRUE without pathlen" do
        bc = R509::Cert::Extensions::BasicConstraints.new(:ca => true)
        bc.is_ca?.should be_true
        bc.path_length.should be_nil
      end

      it "creates CA:TRUE with path_length" do
        bc = R509::Cert::Extensions::BasicConstraints.new(:ca => true, :path_length => 3)
        bc.is_ca?.should be_true
        bc.path_length.should == 3
      end

      it "creates CA:FALSE" do
        bc = R509::Cert::Extensions::BasicConstraints.new(:ca => false)
        bc.is_ca?.should be_false
        bc.path_length.should be_nil
      end

      it "errors when supplying path_length if CA:FALSE" do
        expect {
          R509::Cert::Extensions::BasicConstraints.new(:ca => false, :path_length => 4)
        }.to raise_error(ArgumentError, ":path_length is not allowed when :ca is false")
      end

      it "creates with default criticality" do
        bc = R509::Cert::Extensions::BasicConstraints.new(:ca => false)
        bc.critical?.should be_true
      end

      it "creates with non-default criticality" do
        bc = R509::Cert::Extensions::BasicConstraints.new(:ca => false, :critical => false)
        bc.critical?.should be_false
      end

    end

    context "with constraints for a CA certificate" do
      before :all do
        @extension_value = "CA:TRUE,pathlen:3"
        @is_ca = true
        @pathlen = 3
        @allows_sub_ca = true
      end

      it_should_behave_like "a correct R509 BasicConstraints object", false
      it_should_behave_like "a correct R509 BasicConstraints object", true
    end

    context "with constraints for a CA certificate with no path length" do
      before :all do
        @extension_value = "CA:TRUE"
        @is_ca = true
        @pathlen = nil
        @allows_sub_ca = true
      end

      it_should_behave_like "a correct R509 BasicConstraints object", false
      it_should_behave_like "a correct R509 BasicConstraints object", true
    end

    context "with constraints for a sub-CA certificate" do
      before :all do
        @extension_value = "CA:TRUE,pathlen:0"
        @is_ca = true
        @pathlen = 0
        @allows_sub_ca = false
      end

      it_should_behave_like "a correct R509 BasicConstraints object", false
      it_should_behave_like "a correct R509 BasicConstraints object", true
    end

    context "with constraints for a non-CA certificate" do
      before :all do
        @extension_value = "CA:FALSE"
        @is_ca = false
        @pathlen = nil
        @allows_sub_ca = false
      end

      it_should_behave_like "a correct R509 BasicConstraints object", false
      it_should_behave_like "a correct R509 BasicConstraints object", true
    end
  end

  context "KeyUsage" do
    context "creation" do
      it "creates with single KU" do
        ku = R509::Cert::Extensions::KeyUsage.new(:key_usage => ['digitalSignature'])
        ku.allowed_uses.should == ['digitalSignature']
      end

      it "creates with multiple KU" do
        ku = R509::Cert::Extensions::KeyUsage.new(:key_usage => ['digitalSignature','keyAgreement'])
        ku.allowed_uses.should == ['digitalSignature','keyAgreement']
      end

      it "creates with default criticality" do
        ku = R509::Cert::Extensions::KeyUsage.new(:key_usage => ['keyAgreement'])
        ku.critical?.should be_false
      end

      it "creates with non-default criticality" do
        ku = R509::Cert::Extensions::KeyUsage.new(:key_usage => ['keyAgreement'], :critical => true)
        ku.critical?.should be_true
      end

    end

    context "with one allowed use" do
      before :all do
        @allowed_uses = [ KeyUsage::AU_DIGITAL_SIGNATURE ]
        @extension_value = @allowed_uses.join( ", " )
      end

      it_should_behave_like "a correct R509 KeyUsage object", false
      it_should_behave_like "a correct R509 KeyUsage object", true
    end

    context "with some allowed uses" do
      before :all do
        # this spec and the one below alternate the uses
        @allowed_uses = [ KeyUsage::AU_DIGITAL_SIGNATURE, KeyUsage::AU_KEY_ENCIPHERMENT, KeyUsage::AU_KEY_AGREEMENT, KeyUsage::AU_CRL_SIGN, KeyUsage::AU_DECIPHER_ONLY ]
        @extension_value = @allowed_uses.join( ", " )
      end

      it_should_behave_like "a correct R509 KeyUsage object", false
      it_should_behave_like "a correct R509 KeyUsage object", true
    end

    context "with some different allowed uses" do
      before :all do
        @allowed_uses = [ KeyUsage::AU_NON_REPUDIATION, KeyUsage::AU_DATA_ENCIPHERMENT, KeyUsage::AU_KEY_CERT_SIGN, KeyUsage::AU_ENCIPHER_ONLY ]
        @extension_value = @allowed_uses.join( ", " )
      end

      it_should_behave_like "a correct R509 KeyUsage object", false
      it_should_behave_like "a correct R509 KeyUsage object", true
    end

    context "with all allowed uses" do
      before :all do
        @allowed_uses = [ KeyUsage::AU_DIGITAL_SIGNATURE, KeyUsage::AU_NON_REPUDIATION,
                 KeyUsage::AU_KEY_ENCIPHERMENT, KeyUsage::AU_DATA_ENCIPHERMENT,
                 KeyUsage::AU_KEY_AGREEMENT, KeyUsage::AU_KEY_CERT_SIGN,
                 KeyUsage::AU_CRL_SIGN, KeyUsage::AU_ENCIPHER_ONLY,
                 KeyUsage::AU_DECIPHER_ONLY ]
        @extension_value = @allowed_uses.join( ", " )
      end

      it_should_behave_like "a correct R509 KeyUsage object", false
      it_should_behave_like "a correct R509 KeyUsage object", true
    end
  end

  context "ExtendedKeyUsage" do
    context "creation" do
      it "creates with single EKU" do
        eku = R509::Cert::Extensions::ExtendedKeyUsage.new(:extended_key_usage => ['serverAuth'])
        eku.allowed_uses.should == ['serverAuth']
      end

      it "creates with multiple EKU" do
        eku = R509::Cert::Extensions::ExtendedKeyUsage.new(:extended_key_usage => ['serverAuth','codeSigning'])
        eku.allowed_uses.should == ['serverAuth','codeSigning']
      end

      it "creates with default criticality" do
        eku = R509::Cert::Extensions::ExtendedKeyUsage.new(:extended_key_usage => ['serverAuth'])
        eku.critical?.should be_false
      end

      it "creates with non-default criticality" do
        eku = R509::Cert::Extensions::ExtendedKeyUsage.new(:extended_key_usage => ['serverAuth'], :critical => true)
        eku.critical?.should be_true
      end

    end

    context "with one allowed use" do
      before :all do
        @allowed_uses = [ ExtendedKeyUsage::AU_WEB_SERVER_AUTH ]
        @extension_value = @allowed_uses.join( ", " )
      end

      it_should_behave_like "a correct R509 ExtendedKeyUsage object", false
      it_should_behave_like "a correct R509 ExtendedKeyUsage object", true
    end

    context "with some allowed uses" do
      before :all do
        # this spec and the one below alternate the uses
        @allowed_uses = [ ExtendedKeyUsage::AU_WEB_SERVER_AUTH, ExtendedKeyUsage::AU_CODE_SIGNING ]
        @extension_value = @allowed_uses.join( ", " )
      end

      it_should_behave_like "a correct R509 ExtendedKeyUsage object", false
      it_should_behave_like "a correct R509 ExtendedKeyUsage object", true
    end

    context "with some different allowed uses" do
      before :all do
        @allowed_uses = [ ExtendedKeyUsage::AU_WEB_CLIENT_AUTH, ExtendedKeyUsage::AU_EMAIL_PROTECTION ]
        @extension_value = @allowed_uses.join( ", " )
      end

      it_should_behave_like "a correct R509 ExtendedKeyUsage object", false
      it_should_behave_like "a correct R509 ExtendedKeyUsage object", true
    end

    context "with all allowed uses" do
      before :all do
        @allowed_uses = [ ExtendedKeyUsage::AU_WEB_SERVER_AUTH, ExtendedKeyUsage::AU_CODE_SIGNING,
                  ExtendedKeyUsage::AU_WEB_CLIENT_AUTH, ExtendedKeyUsage::AU_EMAIL_PROTECTION,
                  ExtendedKeyUsage::AU_TIME_STAMPING, ExtendedKeyUsage::AU_OCSP_SIGNING,
                  ExtendedKeyUsage::AU_ANY_EXTENDED_KEY_USAGE]
        @extension_value = @allowed_uses.join( ", " )
      end

      it_should_behave_like "a correct R509 ExtendedKeyUsage object", false
      it_should_behave_like "a correct R509 ExtendedKeyUsage object", true
    end
  end

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
        expect {
          R509::Cert::Extensions::SubjectKeyIdentifier.new({})
        }.to raise_error(ArgumentError,"You must supply a :public_key")
      end

      it "creates successfully" do
        ski = R509::Cert::Extensions::SubjectKeyIdentifier.new(:public_key => @pk.public_key)
        ski.key.should_not be_nil
      end

      it "creates with default criticality" do
        ski = R509::Cert::Extensions::SubjectKeyIdentifier.new(:public_key => @pk.public_key)
        ski.critical?.should be_false
      end

      it "creates with non-default criticality" do
        ski = R509::Cert::Extensions::SubjectKeyIdentifier.new(:public_key => @pk.public_key, :critical => true)
        ski.critical?.should be_true
      end

    end

    it_should_behave_like "a correct R509 SubjectKeyIdentifier object"
  end

  context "AuthorityKeyIdentifier" do
    before :all do
      @extension_value = "keyid:always,issuer:always"
    end

    context "creation" do
      before :all do
        @cert = TestFixtures.test_ca_cert
      end

      it "errors when not supplying an issuer certificate" do
        expect {
          R509::Cert::Extensions::AuthorityKeyIdentifier.new({})
        }.to raise_error(ArgumentError,'You must supply an OpenSSL::PKey object to :public_key if aki value contains keyid (present by default)')
      end

      it "creates successfully with default value" do
        aki = R509::Cert::Extensions::AuthorityKeyIdentifier.new(:public_key => @cert.public_key)
        aki.key_identifier.should_not be_nil
        aki.authority_cert_issuer.should be_nil
      end

      it "creates successfully with issuer value" do
        aki = R509::Cert::Extensions::AuthorityKeyIdentifier.new(:issuer_subject => @cert.subject, :value => "issuer:always")
        aki.authority_cert_issuer.should_not be_nil
        aki.authority_cert_serial_number.should_not be_nil
      end

      it "creates successfully with issuer+keyid value" do
        aki = R509::Cert::Extensions::AuthorityKeyIdentifier.new(:issuer_subject => @cert.subject, :public_key => @cert.public_key, :value => "issuer:always,keyid:always")
        aki.authority_cert_issuer.should_not be_nil
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

    it_should_behave_like "a correct R509 AuthorityKeyIdentifier object"
  end

  context "SubjectAlternativeName" do
    context "creation" do

      it "errors when not supplying :names" do
        expect {
          R509::Cert::Extensions::SubjectAlternativeName.new({})
        }.to raise_error(ArgumentError,"You must supply an array or R509::ASN1::GeneralNames object to :names")
      end

      it "creates with GeneralNames object" do
        gns = R509::ASN1::GeneralNames.new
        gns.create_item(:type => "rfc822Name", :value => "random string")
        san = R509::Cert::Extensions::SubjectAlternativeName.new(:names => gns)
        san.rfc_822_names.should == ['random string']
      end

      it "creates with a single name" do
        san = R509::Cert::Extensions::SubjectAlternativeName.new(:names => ['domain.com'])
        san.dns_names.should == ['domain.com']
      end

      it "creates with multiple names" do
        san = R509::Cert::Extensions::SubjectAlternativeName.new(:names => ['domain.com','127.0.0.1'])
        san.dns_names.should == ['domain.com']
        san.ip_addresses.should == ['127.0.0.1']
      end

      it "creates with default criticality" do
        san = R509::Cert::Extensions::SubjectAlternativeName.new(:names => ['domain.com'])
        san.critical?.should be_false
      end

      it "creates with non-default criticality" do
        san = R509::Cert::Extensions::SubjectAlternativeName.new(:names => ['domain.com'], :critical => true)
        san.critical?.should be_true
      end

    end

    context "with an unimplemented GeneralName type" do
      it "errors as expected" do
        ef = OpenSSL::X509::ExtensionFactory.new
        ext = ef.create_extension("subjectAltName","otherName:1.2.3.4;IA5STRING:Hello World")
        expect { R509::Cert::Extensions::SubjectAlternativeName.new ext }.to raise_error(R509::R509Error, 'Unimplemented GeneralName tag: 0. At this time R509 does not support GeneralName types other than rfc822Name, dNSName, uniformResourceIdentifier, iPAddress, and directoryName')
      end
    end
    context "with a DNS alternative name only" do
      before :all do
        @dns_names = ["www.test.local"]
        @ip_addresses = []
        @uris = []
        @rfc_822_names = []
        @directory_names = []
        total = [@dns_names,@ip_addresses,@uris,@rfc_822_names,@directory_names].flatten(1)
        gns = R509::ASN1.general_name_parser(total)
        serialized = gns.serialize_names
        @conf = serialized[:conf]
        @extension_value = serialized[:extension_string]
      end

      it_should_behave_like "a correct R509 SubjectAlternativeName object", false
      it_should_behave_like "a correct R509 SubjectAlternativeName object", true
    end

    context "with multiple DNS alternative names only" do
      before :all do
        @dns_names = ["www.test.local", "www2.test.local"]
        @ip_addresses = []
        @uris = []
        @rfc_822_names = []
        @directory_names = []
        total = [@dns_names,@ip_addresses,@uris,@rfc_822_names,@directory_names].flatten(1)
        gns = R509::ASN1.general_name_parser(total)
        serialized = gns.serialize_names
        @conf = serialized[:conf]
        @extension_value = serialized[:extension_string]
      end

      it_should_behave_like "a correct R509 SubjectAlternativeName object", false
      it_should_behave_like "a correct R509 SubjectAlternativeName object", true
    end

    context "with an IP address alternative name only" do
      before :all do
        @dns_names = []
        @ip_addresses = ["203.1.2.3"]
        @rfc_822_names = []
        @uris = []
        @directory_names = []
        total = [@dns_names,@ip_addresses,@uris,@rfc_822_names,@directory_names].flatten(1)
        gns = R509::ASN1.general_name_parser(total)
        serialized = gns.serialize_names
        @conf = serialized[:conf]
        @extension_value = serialized[:extension_string]
      end

      it_should_behave_like "a correct R509 SubjectAlternativeName object", false
      it_should_behave_like "a correct R509 SubjectAlternativeName object", true
    end

    context "with multiple IP address alternative names only" do
      before :all do
        @dns_names = []
        @ip_addresses = ["10.1.2.3", "10.1.2.4"]
        @uris = []
        @rfc_822_names = []
        @directory_names = []
        total = [@dns_names,@ip_addresses,@uris,@rfc_822_names,@directory_names].flatten(1)
        gns = R509::ASN1.general_name_parser(total)
        serialized = gns.serialize_names
        @conf = serialized[:conf]
        @extension_value = serialized[:extension_string]
      end

      it_should_behave_like "a correct R509 SubjectAlternativeName object", false
      it_should_behave_like "a correct R509 SubjectAlternativeName object", true
    end

    context "with an rfc822Name alternative name only" do
      before :all do
        @dns_names = []
        @ip_addresses = []
        @rfc_822_names = ["some@guy.com"]
        @uris = []
        @directory_names = []
        total = [@dns_names,@ip_addresses,@uris,@rfc_822_names,@directory_names].flatten(1)
        gns = R509::ASN1.general_name_parser(total)
        serialized = gns.serialize_names
        @conf = serialized[:conf]
        @extension_value = serialized[:extension_string]
      end

      it_should_behave_like "a correct R509 SubjectAlternativeName object", false
      it_should_behave_like "a correct R509 SubjectAlternativeName object", true
    end

    context "with multiple rfc822Name alternative names only" do
      before :all do
        @dns_names = []
        @ip_addresses = []
        @rfc_822_names = ["some@guy.com","other@guy.com"]
        @uris = []
        @directory_names = []
        total = [@dns_names,@ip_addresses,@uris,@rfc_822_names,@directory_names].flatten(1)
        gns = R509::ASN1.general_name_parser(total)
        serialized = gns.serialize_names
        @conf = serialized[:conf]
        @extension_value = serialized[:extension_string]
      end

      it_should_behave_like "a correct R509 SubjectAlternativeName object", false
      it_should_behave_like "a correct R509 SubjectAlternativeName object", true
    end

    context "with a URI alternative name only" do
      before :all do
        @dns_names = []
        @ip_addresses = []
        @rfc_822_names = []
        @uris = ["http://www.test.local"]
        @directory_names = []
        total = [@dns_names,@ip_addresses,@uris,@rfc_822_names,@directory_names].flatten(1)
        gns = R509::ASN1.general_name_parser(total)
        serialized = gns.serialize_names
        @conf = serialized[:conf]
        @extension_value = serialized[:extension_string]
      end

      it_should_behave_like "a correct R509 SubjectAlternativeName object", false
      it_should_behave_like "a correct R509 SubjectAlternativeName object", true
    end

    context "with multiple URI alternative names only" do
      before :all do
        @dns_names = []
        @ip_addresses = []
        @rfc_822_names = []
        @uris = ["http://www.test.local","http://www2.test.local"]
        @directory_names = []
        total = [@dns_names,@ip_addresses,@uris,@rfc_822_names,@directory_names].flatten(1)
        gns = R509::ASN1.general_name_parser(total)
        serialized = gns.serialize_names
        @conf = serialized[:conf]
        @extension_value = serialized[:extension_string]
      end

      it_should_behave_like "a correct R509 SubjectAlternativeName object", false
      it_should_behave_like "a correct R509 SubjectAlternativeName object", true
    end

    context "with a directoryName alternative name only" do
      before :all do
        @dns_names = []
        @ip_addresses = []
        @rfc_822_names = []
        @uris = []
        @directory_names = [
          [['CN','langui.sh'],['O','org'],['L','locality']]
        ]
        total = [@dns_names,@ip_addresses,@uris,@rfc_822_names,@directory_names].flatten(1)
        gns = R509::ASN1.general_name_parser(total)
        serialized = gns.serialize_names
        @conf = serialized[:conf]
        @extension_value = serialized[:extension_string]
      end

      it_should_behave_like "a correct R509 SubjectAlternativeName object", false
      it_should_behave_like "a correct R509 SubjectAlternativeName object", true
    end

    context "with multiple directoryName alternative names only" do
      before :all do
        @dns_names = []
        @ip_addresses = []
        @rfc_822_names = []
        @uris = []
        @directory_names = [
          [['CN','langui.sh'],['O','org'],['L','locality']],
          [['CN','otherdomain.com'],['O','org-like']]
        ]
        total = [@dns_names,@ip_addresses,@uris,@rfc_822_names,@directory_names].flatten(1)
        gns = R509::ASN1.general_name_parser(total)
        serialized = gns.serialize_names
        @conf = serialized[:conf]
        @extension_value = serialized[:extension_string]
      end

      it_should_behave_like "a correct R509 SubjectAlternativeName object", false
      it_should_behave_like "a correct R509 SubjectAlternativeName object", true
    end

    context "with multiple different alternative names" do
      before :all do
        @dns_names = ["www.test.local"]
        @ip_addresses = ["10.1.2.3"]
        @rfc_822_names = ["myemail@email.com"]
        @uris = ["http://www.test.local"]
        @directory_names = [
          [['CN','langui.sh'],['O','org'],['L','locality']]
        ]
        total = [@dns_names,@ip_addresses,@uris,@rfc_822_names,@directory_names].flatten(1)
        gns = R509::ASN1.general_name_parser(total)
        serialized = gns.serialize_names
        @conf = serialized[:conf]
        @extension_value = serialized[:extension_string]
      end

      it_should_behave_like "a correct R509 SubjectAlternativeName object", false
      it_should_behave_like "a correct R509 SubjectAlternativeName object", true
    end
  end
  context "AuthorityInfoAccess" do
    context "creation" do
      it "creates with GeneralNames object" do
        gns = R509::ASN1::GeneralNames.new
        gns.create_item(:type => "rfc822Name", :value => "random string")
        aia = R509::Cert::Extensions::AuthorityInfoAccess.new(
          :ocsp_location => gns,
          :ca_issuers_location => gns
        )
        aia.ocsp.rfc_822_names.should == ['random string']
        aia.ca_issuers.rfc_822_names.should == ['random string']
      end

      it "creates with one OCSP" do
        aia = R509::Cert::Extensions::AuthorityInfoAccess.new(
          :ocsp_location => ['http://ocsp.domain.com']
        )
        aia.ocsp.uris.should == ['http://ocsp.domain.com']
      end

      it "creates with multiple OCSP" do
        aia = R509::Cert::Extensions::AuthorityInfoAccess.new(
          :ocsp_location => ['http://ocsp.domain.com','http://ocsp2.domain.com']
        )
        aia.ocsp.uris.should == ['http://ocsp.domain.com','http://ocsp2.domain.com']
      end

      it "creates with one caIssuers" do
        aia = R509::Cert::Extensions::AuthorityInfoAccess.new(
          :ca_issuers_location => ['http://www.domain.com']
        )
        aia.ca_issuers.uris.should == ['http://www.domain.com']
      end

      it "creates with multiple caIssuers" do
        aia = R509::Cert::Extensions::AuthorityInfoAccess.new(
          :ca_issuers_location => ['http://www.domain.com','http://www2.domain.com']
        )
        aia.ca_issuers.uris.should == ['http://www.domain.com','http://www2.domain.com']
      end

      it "creates with caIssuers+OCSP" do
        aia = R509::Cert::Extensions::AuthorityInfoAccess.new(
          :ca_issuers_location => ['http://www.domain.com'],
          :ocsp_location => ['http://ocsp.domain.com']
        )
        aia.ca_issuers.uris.should == ['http://www.domain.com']
        aia.ocsp.uris.should == ['http://ocsp.domain.com']
      end

      it "creates with default criticality" do
        aia = R509::Cert::Extensions::AuthorityInfoAccess.new(
          :ocsp_location => ['http://ocsp.domain.com']
        )
        aia.critical?.should be_false
      end

      it "creates with non-default criticality" do
        aia = R509::Cert::Extensions::AuthorityInfoAccess.new(
          :ocsp_location => ['http://ocsp.domain.com'],
          :critical => true
        )
        aia.critical?.should be_true
      end

    end

    context "with a CA Issuers URI only" do
      before :all do
        @ca_issuers_uris = ["http://www.test.local/ca.cert"]
        @ocsp_uris = []
        @extension_value = "caIssuers;URI:#{@ca_issuers_uris.join(",caIssuers;URI:")}"
      end

      it_should_behave_like "a correct R509 AuthorityInfoAccess object", false
      it_should_behave_like "a correct R509 AuthorityInfoAccess object", true
    end

    context "with multiple CA Issuers URIs only" do
      before :all do
        @ca_issuers_uris = ["http://www.test.local/ca.cert", "http://www.test.local/subca.cert"]
        @ocsp_uris = []
        @extension_value = "caIssuers;URI:#{@ca_issuers_uris.join(",caIssuers;URI:")}"
      end

      it_should_behave_like "a correct R509 AuthorityInfoAccess object", false
      it_should_behave_like "a correct R509 AuthorityInfoAccess object", true
    end

    context "with an OCSP URI only" do
      before :all do
        @ca_issuers_uris = []
        @ocsp_uris = ["http://www.test.local"]
        @extension_value = "OCSP;URI:#{@ocsp_uris.join(",OCSP;URI:")}"
      end

      it_should_behave_like "a correct R509 AuthorityInfoAccess object", false
      it_should_behave_like "a correct R509 AuthorityInfoAccess object", true
    end

    context "with multiple OCSP URIs only" do
      before :all do
        @ca_issuers_uris = []
        @ocsp_uris = ["http://www.test.local", "http://www2.test.local"]
        @extension_value = "OCSP;URI:#{@ocsp_uris.join(",OCSP;URI:")}"
      end

      it_should_behave_like "a correct R509 AuthorityInfoAccess object", false
      it_should_behave_like "a correct R509 AuthorityInfoAccess object", true
    end

    context "with both a CA Issuers URI and an OCSP URI" do
      before :all do
        @ca_issuers_uris = ["http://www.test.local/ca.cert"]
        @ocsp_uris = ["http://www.test.local"]
        @extension_value = "caIssuers;URI:#{@ca_issuers_uris.join(",caIssuers;URI:")},OCSP;URI:#{@ocsp_uris.join(",OCSP;URI:")}"
      end

      it_should_behave_like "a correct R509 AuthorityInfoAccess object", false
      it_should_behave_like "a correct R509 AuthorityInfoAccess object", true
    end
  end

  context "CRLDistributionPoints" do
    context "creation" do
      it "creates with GeneralNames object" do
        gns = R509::ASN1::GeneralNames.new
        gns.create_item(:type => "rfc822Name", :value => "random string")
        cdp = R509::Cert::Extensions::CRLDistributionPoints.new(:cdp_location => gns)
        cdp.crl.rfc_822_names.should == ['random string']
      end

      it "creates with one CDP" do
        cdp = R509::Cert::Extensions::CRLDistributionPoints.new(:cdp_location => ['http://crl.r509.org/ca.crl'])
        cdp.crl.uris.should == ['http://crl.r509.org/ca.crl']
      end

      it "creates with multiple CDP" do
        cdp = R509::Cert::Extensions::CRLDistributionPoints.new(:cdp_location => ['http://crl.r509.org/ca.crl','http://2.com/test.crl'])
        cdp.crl.uris.should == ['http://crl.r509.org/ca.crl','http://2.com/test.crl']
      end

      it "creates with default criticality" do
        cdp = R509::Cert::Extensions::CRLDistributionPoints.new(:cdp_location => ['http://crl.r509.org/ca.crl'])
        cdp.critical?.should be_false
      end

      it "creates with non-default criticality" do
        cdp = R509::Cert::Extensions::CRLDistributionPoints.new(:cdp_location => ['http://crl.r509.org/ca.crl'], :critical => true)
        cdp.critical?.should be_true
      end

    end

    context "with a single CRL URI" do
      before :all do
        @crl_uris = ["http://www.test.local/ca.crl"]
        @extension_value = "URI:#{@crl_uris.join(",URI:")}"
      end

      it_should_behave_like "a correct R509 CRLDistributionPoints object", false
      it_should_behave_like "a correct R509 CRLDistributionPoints object", true
    end

    context "with multiple CRL URIs" do
      before :all do
        @crl_uris = ["http://www.test.local/ca.crl", "http://www.test.local/subca.crl"]
        @extension_value = "URI:#{@crl_uris.join(",URI:")}"
      end

      it_should_behave_like "a correct R509 CRLDistributionPoints object", false
      it_should_behave_like "a correct R509 CRLDistributionPoints object", true
    end
  end

  context "OCSPNoCheck" do
    context "creation" do
      it "creates an extension when passed a hash" do
        no_check = R509::Cert::Extensions::OCSPNoCheck.new({})
        no_check.should_not be_nil
      end

      it "creates with default criticality" do
        no_check = R509::Cert::Extensions::OCSPNoCheck.new({})
        no_check.critical?.should be_false
      end

      it "creates with non-default criticality" do
        no_check = R509::Cert::Extensions::OCSPNoCheck.new(:critical => true)
        no_check.critical?.should be_true
      end

    end

    it_should_behave_like "a correct R509 OCSPNoCheck object", false
    it_should_behave_like "a correct R509 OCSPNoCheck object", true
  end

  context "CertificatePolicies" do
    before :all do
      @policy_data = "0\x81\x90\x06\x03U\x1D \x04\x81\x880\x81\x850\x81\x82\x06\v`\x86H\x01\xE09\x01\x02\x03\x04\x010s0\"\x06\b+\x06\x01\x05\x05\a\x02\x01\x16\x16http://example.com/cps0 \x06\b+\x06\x01\x05\x05\a\x02\x01\x16\x14http://other.com/cps0+\x06\b+\x06\x01\x05\x05\a\x02\x020\x1F0\x16\x16\x06my org0\f\x02\x01\x01\x02\x01\x02\x02\x01\x03\x02\x01\x04\x1A\x05thing"
    end

    context "creation" do
      it "creates with one policy" do
        cp = R509::Cert::Extensions::CertificatePolicies.new(
          :policies => [{ :policy_identifier => "2.16.840.1.12345.1.2.3.4.1",
            :cps_uris => ["http://example.com/cps","http://other.com/cps"],
            :user_notices => [ {:explicit_text => "thing", :organization => "my org", :notice_numbers => "1,2,3,4"} ]
          }]
        )
        cp.should_not be_nil
        cp.policies.count.should == 1
        cp.policies[0].policy_identifier.should == "2.16.840.1.12345.1.2.3.4.1"
        cp.policies[0].policy_qualifiers.cps_uris.should == ["http://example.com/cps", "http://other.com/cps"]
        cp.policies[0].policy_qualifiers.user_notices.count.should == 1
        un = cp.policies[0].policy_qualifiers.user_notices[0]
        un.notice_reference.notice_numbers.should == [1,2,3,4]
        un.notice_reference.organization.should == 'my org'
        un.explicit_text.should == "thing"
      end

      it "creates with multiple policies" do
        cp = R509::Cert::Extensions::CertificatePolicies.new(
          :policies => [{ :policy_identifier => "2.16.840.1.99999.21.234",
            :cps_uris => ["http://example.com/cps","http://other.com/cps"],
            :user_notices => [ {:explicit_text => "this is a great thing", :organization => "my org", :notice_numbers => "1,2,3,4"} ]
          },
          {
            :policy_identifier => "2.16.840.1.99999.21.235",
            :cps_uris => ["http://example.com/cps2"],
            :user_notices => [{:explicit_text => "this is a bad thing", :organization => "another org", :notice_numbers => "3,2,1"}, {:explicit_text => "another user notice"}]
          },
          {
            :policy_identifier => "2.16.840.1.99999.0"
          }]
        )
        cp.should_not be_nil
        cp.policies.count.should == 3
        p0 = cp.policies[0]
        p0.policy_identifier.should == "2.16.840.1.99999.21.234"
        p0.policy_qualifiers.cps_uris.should == ["http://example.com/cps", "http://other.com/cps"]
        p0.policy_qualifiers.user_notices.count.should == 1
        un0 = p0.policy_qualifiers.user_notices[0]
        un0.notice_reference.notice_numbers.should == [1,2,3,4]
        un0.notice_reference.organization.should == "my org"
        un0.explicit_text.should == "this is a great thing"
        p1 = cp.policies[1]
        p1.policy_identifier.should == "2.16.840.1.99999.21.235"
        p1.policy_qualifiers.cps_uris.should == ["http://example.com/cps2"]
        p1.policy_qualifiers.user_notices.count.should == 2
        un1 = p1.policy_qualifiers.user_notices[0]
        un1.notice_reference.notice_numbers.should == [3,2,1]
        un1.notice_reference.organization.should == "another org"
        un1.explicit_text.should == 'this is a bad thing'
        un2 = p1.policy_qualifiers.user_notices[1]
        un2.notice_reference.should be_nil
        un2.explicit_text.should == "another user notice"
        p2 = cp.policies[2]
        p2.policy_identifier.should == "2.16.840.1.99999.0"
        p2.policy_qualifiers.should be_nil
      end

      it "creates with default criticality" do
        cp = R509::Cert::Extensions::CertificatePolicies.new(
          :policies => [{ :policy_identifier => "2.16.840.1.12345.1.2.3.4.1" }]
        )
        cp.critical?.should be_false
      end

      it "creates with non-default criticality" do
        cp = R509::Cert::Extensions::CertificatePolicies.new(
          :policies => [{ :policy_identifier => "2.16.840.1.12345.1.2.3.4.1" }],
          :critical => true
        )
        cp.critical?.should be_true
      end

    end

    it_should_behave_like "a correct R509 CertificatePolicies object"
  end

  context "InhibitAnyPolicy" do
    before :all do
      @skip_certs = 3
    end

    context "creation" do
      it "creates with a positive skip #" do
        iap = R509::Cert::Extensions::InhibitAnyPolicy.new(:skip_certs => 1)
        iap.skip_certs.should == 1
      end

      it "creates with default criticality" do
        iap = R509::Cert::Extensions::InhibitAnyPolicy.new(:skip_certs => 1)
        iap.critical?.should == true
      end

      it "creates with non-default criticality" do
        iap = R509::Cert::Extensions::InhibitAnyPolicy.new(:skip_certs => 1, :critical => false)
        iap.critical?.should == false
      end

    end

    it_should_behave_like "a correct R509 InhibitAnyPolicy object", false
    it_should_behave_like "a correct R509 InhibitAnyPolicy object", true
  end

  context "PolicyConstraints" do
    context "creation" do
      it "creates with require explicit policy" do
        pc = R509::Cert::Extensions::PolicyConstraints.new(
          :require_explicit_policy => 1
        )
        pc.require_explicit_policy.should == 1
      end

      it "creates with inhibit policy mapping" do
        pc = R509::Cert::Extensions::PolicyConstraints.new(
          :inhibit_policy_mapping => 1
        )
        pc.inhibit_policy_mapping.should == 1
      end

      it "creates with both" do
        pc = R509::Cert::Extensions::PolicyConstraints.new(
          :inhibit_policy_mapping => 1,
          :require_explicit_policy => 3
        )
        pc.inhibit_policy_mapping.should == 1
        pc.require_explicit_policy.should == 3
      end

      it "creates with default criticality" do
        pc = R509::Cert::Extensions::PolicyConstraints.new(
          :inhibit_policy_mapping => 1
        )
        pc.critical?.should == true
      end

      it "creates with non-default criticality" do
        pc = R509::Cert::Extensions::PolicyConstraints.new(
          :inhibit_policy_mapping => 1,
          :critical => false
        )
        pc.critical?.should == false
      end

    end
    context "with just require" do
      before :all do
        @require_explicit_policy = 2
        @inhibit_policy_mapping = nil
        @extension_value = "requireExplicitPolicy:#{@require_explicit_policy}"
      end
      it_should_behave_like "a correct R509 PolicyConstraints object", false
      it_should_behave_like "a correct R509 PolicyConstraints object", true
    end
    context "with just inhibit" do
      before :all do
        @require_explicit_policy = nil
        @inhibit_policy_mapping = 3
        @extension_value = "inhibitPolicyMapping:#{@inhibit_policy_mapping}"
      end
      it_should_behave_like "a correct R509 PolicyConstraints object", false
      it_should_behave_like "a correct R509 PolicyConstraints object", true
    end
    context "with both require and inhibit" do
      before :all do
        @require_explicit_policy = 2
        @inhibit_policy_mapping = 3
        @extension_value = "requireExplicitPolicy:#{@require_explicit_policy},inhibitPolicyMapping:#{@inhibit_policy_mapping}"
      end
      it_should_behave_like "a correct R509 PolicyConstraints object", false
      it_should_behave_like "a correct R509 PolicyConstraints object", true
    end

  end

  context "NameConstraints" do
    context "creation" do
      it "creates with one permitted" do
        nc = R509::Cert::Extensions::NameConstraints.new(
          :permitted => [ { :type => 'dNSName', :value => 'domain.com' }]
        )
        nc.permitted.size.should == 1
        nc.permitted[0].value.should == 'domain.com'
      end

      it "creates with multiple permitted" do
        nc = R509::Cert::Extensions::NameConstraints.new(
          :permitted => [
            { :type => 'dNSName', :value => 'domain.com' },
            { :type => 'iPAddress', :value => '127.0.0.1/255.255.255.255' }
          ]
        )
        nc.permitted.size.should == 2
        nc.permitted[0].value.should == 'domain.com'
        nc.permitted[1].value.should == '127.0.0.1/255.255.255.255'
      end

      it "creates with one excluded" do
        nc = R509::Cert::Extensions::NameConstraints.new(
          :excluded => [ { :type => 'dNSName', :value => 'domain.com' }]
        )
        nc.excluded.size.should == 1
        nc.excluded[0].value.should == 'domain.com'
      end

      it "creates with multiple excluded" do
        nc = R509::Cert::Extensions::NameConstraints.new(
          :excluded => [
            { :type => 'dNSName', :value => 'domain.com' },
            { :type => 'iPAddress', :value => '127.0.0.1/255.255.255.255' }
          ]
        )
        nc.excluded.size.should == 2
        nc.excluded[0].value.should == 'domain.com'
        nc.excluded[1].value.should == '127.0.0.1/255.255.255.255'
      end

      it "creates with both" do
        nc = R509::Cert::Extensions::NameConstraints.new(
          :permitted => [
            { :type => 'dNSName', :value => 'domain.com' },
            { :type => 'iPAddress', :value => '127.0.0.1/255.255.255.255' }
          ],
          :excluded => [
            { :type => 'dNSName', :value => 'domain.com' },
            { :type => 'iPAddress', :value => '127.0.0.1/255.255.255.255' }
          ]
        )
        nc.excluded.size.should == 2
        nc.excluded[0].value.should == 'domain.com'
        nc.excluded[1].value.should == '127.0.0.1/255.255.255.255'
        nc.permitted.size.should == 2
        nc.permitted[0].value.should == 'domain.com'
        nc.permitted[1].value.should == '127.0.0.1/255.255.255.255'
      end

      it "creates with default criticality" do
        nc = R509::Cert::Extensions::NameConstraints.new(
          :excluded => [ { :type => 'dNSName', :value => 'domain.com' }]
        )
        nc.critical?.should == true
      end

      it "creates with non-default criticality" do
        nc = R509::Cert::Extensions::NameConstraints.new(
          :excluded => [ { :type => 'dNSName', :value => 'domain.com' }],
          :critical => false
        )
        nc.critical?.should == false
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
        permitted = gns.names.map { |name|
          serialized = name.serialize_name
          @conf << serialized[:conf]
          "permitted;" + serialized[:extension_string]
        }.join(",")
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
        permitted = gns.names.map { |name|
          serialized = name.serialize_name
          @conf << serialized[:conf]
          "permitted;" + serialized[:extension_string]
        }.join(",")
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
        excluded = egns.names.map { |name|
          serialized = name.serialize_name
          @conf << serialized[:conf]
          "excluded;" + serialized[:extension_string]
        }.join(",")
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
        excluded = egns.names.map { |name|
          serialized = name.serialize_name
          @conf << serialized[:conf]
          "excluded;" + serialized[:extension_string]
        }.join(",")
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
        permitted = gns.names.map { |name|
          serialized = name.serialize_name
          @conf << serialized[:conf]
          "permitted;" + serialized[:extension_string]
        }.join(",")
        egns = R509::ASN1::GeneralNames.new
        @excluded.each do |name|
          egns.add_item(name)
        end
        excluded = egns.names.map { |name|
          serialized = name.serialize_name
          @conf << serialized[:conf]
          "excluded;" + serialized[:extension_string]
        }.join(",")
        @extension_value = permitted + "," + excluded
        @conf = @conf.join("\n")
      end

      it_should_behave_like "a correct R509 NameConstraints object", false
      it_should_behave_like "a correct R509 NameConstraints object", true
    end
  end
end
