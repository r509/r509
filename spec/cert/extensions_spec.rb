require 'spec_helper'

include R509::Cert::Extensions

shared_examples_for "a correctly implemented wrap_openssl_extensions" do
  before :each do
    @r509_extensions = R509::Cert::Extensions.wrap_openssl_extensions( @openssl_extensions )

    @r509_classes = [ BasicConstraints, KeyUsage, ExtendedKeyUsage,
            SubjectKeyIdentifier, AuthorityKeyIdentifier,
            SubjectAlternativeName, AuthorityInfoAccess,
            CrlDistributionPoints, OCSPNoCheck ]
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

shared_examples_for "a correct R509 BasicConstraints object" do
  before :all do
    extension_name = "basicConstraints"
    klass = BasicConstraints
    openssl_ext = OpenSSL::X509::Extension.new( extension_name, @extension_value )
    @r509_ext = klass.new( openssl_ext )
  end

  it "is_ca? should correctly report whether it's a CA certificate" do
    @r509_ext.is_ca?.should == @is_ca
  end

  it "the path length should be correct" do
    @r509_ext.path_length.should == @pathlen
  end

  it "allows_sub_ca? should correctly report whether its path length allows it to issue CA certs" do
    @r509_ext.allows_sub_ca?.should == @allows_sub_ca
  end
end

shared_examples_for "a correct R509 KeyUsage object" do
  before :all do
    extension_name = "keyUsage"
    klass = KeyUsage
    openssl_ext = OpenSSL::X509::Extension.new( extension_name, @extension_value )
    @r509_ext = klass.new( openssl_ext )
  end

  it "allowed_uses should be non-nil" do
    @r509_ext.allowed_uses.should_not == nil
  end

  it "allowed_uses should be correct" do
    @r509_ext.allowed_uses.should == @allowed_uses
  end

  it "the individual allowed-use functions should be correct" do
    @r509_ext.digital_signature?.should == @allowed_uses.include?( KeyUsage::AU_DIGITAL_SIGNATURE )
    @r509_ext.non_repudiation?.should == @allowed_uses.include?( KeyUsage::AU_NON_REPUDIATION )
    @r509_ext.key_encipherment?.should == @allowed_uses.include?( KeyUsage::AU_KEY_ENCIPHERMENT )
    @r509_ext.data_encipherment?.should == @allowed_uses.include?( KeyUsage::AU_DATA_ENCIPHERMENT )
    @r509_ext.key_agreement?.should == @allowed_uses.include?( KeyUsage::AU_KEY_AGREEMENT )
    @r509_ext.certificate_sign?.should == @allowed_uses.include?( KeyUsage::AU_CERTIFICATE_SIGN )
    @r509_ext.crl_sign?.should == @allowed_uses.include?( KeyUsage::AU_CRL_SIGN )
    @r509_ext.encipher_only?.should == @allowed_uses.include?( KeyUsage::AU_ENCIPHER_ONLY )
    @r509_ext.decipher_only?.should == @allowed_uses.include?( KeyUsage::AU_DECIPHER_ONLY )
  end
end

shared_examples_for "a correct R509 ExtendedKeyUsage object" do
  before :all do
    extension_name = "extendedKeyUsage"
    klass = ExtendedKeyUsage
    openssl_ext = OpenSSL::X509::Extension.new( extension_name, @extension_value )
    @r509_ext = klass.new( openssl_ext )
  end

  it "allowed_uses should be non-nil" do
    @r509_ext.allowed_uses.should_not == nil
  end

  it "allowed_uses should be correct" do
    @r509_ext.allowed_uses.should == @allowed_uses
  end

  it "the individual allowed-use functions should be correct" do
    @r509_ext.web_server_authentication?.should == @allowed_uses.include?( ExtendedKeyUsage::AU_WEB_SERVER_AUTH )
    @r509_ext.web_client_authentication?.should == @allowed_uses.include?( ExtendedKeyUsage::AU_WEB_CLIENT_AUTH )
    @r509_ext.code_signing?.should == @allowed_uses.include?( ExtendedKeyUsage::AU_CODE_SIGNING )
    @r509_ext.email_protection?.should == @allowed_uses.include?( ExtendedKeyUsage::AU_EMAIL_PROTECTION )
    @r509_ext.ocsp_signing?.should == @allowed_uses.include?( ExtendedKeyUsage::AU_OCSP_SIGNING )
    @r509_ext.time_stamping?.should == @allowed_uses.include?( ExtendedKeyUsage::AU_TIME_STAMPING )
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
    openssl_ext = OpenSSL::X509::Extension.new( extension_name, @extension_value )
    @r509_ext = klass.new( openssl_ext )
  end

  #TODO
end

shared_examples_for "a correct R509 SubjectAlternativeName object" do
  before :all do
    extension_name = "subjectAltName"
    klass = SubjectAlternativeName
    openssl_ext = OpenSSL::X509::Extension.new( extension_name, @extension_value )
    @r509_ext = klass.new( openssl_ext )
  end

  it "dns_names should be correct" do
    @r509_ext.dns_names.should == @dns_names
  end

  it "ip_addresses should be correct" do
    @r509_ext.ip_addresses.should == @ip_addresses
  end

  it "uris should be correct" do
    @r509_ext.uris.should == @uris
  end
end

shared_examples_for "a correct R509 AuthorityInfoAccess object" do
  before :all do
    extension_name = "authorityInfoAccess"
    klass = AuthorityInfoAccess
    openssl_ext = OpenSSL::X509::Extension.new( extension_name, @extension_value )
    @r509_ext = klass.new( openssl_ext )
  end

  it "ca_issuers_uri should be correct" do
    @r509_ext.ca_issuers_uris.should == @ca_issuers_uris
  end

  it "ocsp_uri should be correct" do
    @r509_ext.ocsp_uris.should == @ocsp_uris
  end
end

shared_examples_for "a correct R509 CrlDistributionPoints object" do
  before :all do
    extension_name = "crlDistributionPoints"
    klass = CrlDistributionPoints
    openssl_ext = OpenSSL::X509::Extension.new( extension_name, @extension_value )
    @r509_ext = klass.new( openssl_ext )
  end

  it "crl_uri should be correct" do
    @r509_ext.crl_uris.should == @crl_uris
  end
end

shared_examples_for "a correct R509 OCSPNoCheck object" do
  before :all do
    extension_name = "noCheck"
    klass = OCSPNoCheck
    openssl_ext = OpenSSL::X509::Extension.new( extension_name, "irrelevant")
    @r509_ext = klass.new( openssl_ext )
  end

  it "has the expected type" do
    @r509_ext.oid.should == "noCheck"
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
          @wrappable_extensions << OpenSSL::X509::Extension.new( "basicConstraints", "CA:TRUE;pathlen:0" )

          @unknown_extensions = []

          @openssl_extensions = @wrappable_extensions + @unknown_extensions
        end

        it_should_behave_like "a correctly implemented wrap_openssl_extensions"
        it_should_behave_like "a correctly implemented get_unknown_extensions"
      end

      context "with all implemented extensions" do
        before :each do
          @wrappable_extensions = []
          @wrappable_extensions << OpenSSL::X509::Extension.new( "basicConstraints", "CA:TRUE;pathlen:0" )
          @wrappable_extensions << OpenSSL::X509::Extension.new( "keyUsage", KeyUsage::AU_DIGITAL_SIGNATURE )
          @wrappable_extensions << OpenSSL::X509::Extension.new( "extendedKeyUsage", ExtendedKeyUsage::AU_WEB_SERVER_AUTH )
          @wrappable_extensions << OpenSSL::X509::Extension.new( "subjectKeyIdentifier", "00:11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF:00:11:22" )
          @wrappable_extensions << OpenSSL::X509::Extension.new( "authorityKeyIdentifier", "keyid:always" )
          @wrappable_extensions << OpenSSL::X509::Extension.new( "subjectAltName", "DNS:www.test.local" )
          @wrappable_extensions << OpenSSL::X509::Extension.new( "authorityInfoAccess", "CA Issuers - URI:http://www.test.local" )
          @wrappable_extensions << OpenSSL::X509::Extension.new( "crlDistributionPoints", "URI:http://www.test.local" )

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
          @wrappable_extensions << OpenSSL::X509::Extension.new( "basicConstraints", "CA:TRUE;pathlen:0" )

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
          @wrappable_extensions << OpenSSL::X509::Extension.new( "basicConstraints", "CA:TRUE;pathlen:0" )
          @wrappable_extensions << OpenSSL::X509::Extension.new( "basicConstraints", "CA:TRUE;pathlen:1" )

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
          @wrappable_extensions << OpenSSL::X509::Extension.new( "basicConstraints", "CA:TRUE;pathlen:0" )

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
    context "with constraints for a CA certificate" do
      before :all do
        @extension_value = "CA:TRUE;pathlen:1"
        @is_ca = true
        @pathlen = 1
        @allows_sub_ca = true
      end

      it_should_behave_like "a correct R509 BasicConstraints object"
    end

    context "with constraints for a sub-CA certificate" do
      before :all do
        @extension_value = "CA:TRUE;pathlen:0"
        @is_ca = true
        @pathlen = 0
        @allows_sub_ca = false
      end

      it_should_behave_like "a correct R509 BasicConstraints object"
    end

    context "with constraints for a non-CA certificate" do
      before :all do
        @extension_value = "CA:FALSE"
        @is_ca = false
        @pathlen = nil
        @allows_sub_ca = false
      end

      it_should_behave_like "a correct R509 BasicConstraints object"
    end
  end

  context "KeyUsage" do
    context "with one allowed use" do
      before :all do
        @allowed_uses = [ KeyUsage::AU_DIGITAL_SIGNATURE ]
        @extension_value = @allowed_uses.join( ", " )
      end

      it_should_behave_like "a correct R509 KeyUsage object"
    end

    context "with some allowed uses" do
      before :all do
        # this spec and the one below alternate the uses
        @allowed_uses = [ KeyUsage::AU_DIGITAL_SIGNATURE, KeyUsage::AU_KEY_ENCIPHERMENT, KeyUsage::AU_KEY_AGREEMENT, KeyUsage::AU_CRL_SIGN, KeyUsage::AU_DECIPHER_ONLY ]
        @extension_value = @allowed_uses.join( ", " )
      end

      it_should_behave_like "a correct R509 KeyUsage object"
    end

    context "with some different allowed uses" do
      before :all do
        @allowed_uses = [ KeyUsage::AU_NON_REPUDIATION, KeyUsage::AU_DATA_ENCIPHERMENT, KeyUsage::AU_CERTIFICATE_SIGN, KeyUsage::AU_ENCIPHER_ONLY ]
        @extension_value = @allowed_uses.join( ", " )
      end

      it_should_behave_like "a correct R509 KeyUsage object"
    end

    context "with all allowed uses" do
      before :all do
        @allowed_uses = [ KeyUsage::AU_DIGITAL_SIGNATURE, KeyUsage::AU_KEY_ENCIPHERMENT,
                 KeyUsage::AU_KEY_AGREEMENT, KeyUsage::AU_CRL_SIGN, KeyUsage::AU_DECIPHER_ONLY,
                 KeyUsage::AU_NON_REPUDIATION, KeyUsage::AU_DATA_ENCIPHERMENT,
                 KeyUsage::AU_CERTIFICATE_SIGN, KeyUsage::AU_ENCIPHER_ONLY ]
        @extension_value = @allowed_uses.join( ", " )
      end

      it_should_behave_like "a correct R509 KeyUsage object"
    end
  end

  context "ExtendedKeyUsage" do
    context "with one allowed use" do
      before :all do
        @allowed_uses = [ ExtendedKeyUsage::AU_WEB_SERVER_AUTH ]
        @extension_value = @allowed_uses.join( ", " )
      end

      it_should_behave_like "a correct R509 ExtendedKeyUsage object"
    end

    context "with some allowed uses" do
      before :all do
        # this spec and the one below alternate the uses
        @allowed_uses = [ ExtendedKeyUsage::AU_WEB_SERVER_AUTH, ExtendedKeyUsage::AU_CODE_SIGNING ]
        @extension_value = @allowed_uses.join( ", " )
      end

      it_should_behave_like "a correct R509 ExtendedKeyUsage object"
    end

    context "with some different allowed uses" do
      before :all do
        @allowed_uses = [ ExtendedKeyUsage::AU_WEB_CLIENT_AUTH, ExtendedKeyUsage::AU_EMAIL_PROTECTION ]
        @extension_value = @allowed_uses.join( ", " )
      end

      it_should_behave_like "a correct R509 ExtendedKeyUsage object"
    end

    context "with all allowed uses" do
      before :all do
        @allowed_uses = [ ExtendedKeyUsage::AU_WEB_SERVER_AUTH, ExtendedKeyUsage::AU_CODE_SIGNING,
                  ExtendedKeyUsage::AU_WEB_CLIENT_AUTH, ExtendedKeyUsage::AU_EMAIL_PROTECTION,
                  ExtendedKeyUsage::AU_TIME_STAMPING, ExtendedKeyUsage::AU_OCSP_SIGNING]
        @extension_value = @allowed_uses.join( ", " )
      end

      it_should_behave_like "a correct R509 ExtendedKeyUsage object"
    end
  end

  context "SubjectKeyIdentifier" do
    before :all do
      @extension_value = "00:11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF:00:11:22"
      @key = @extension_value
    end

    it_should_behave_like "a correct R509 SubjectKeyIdentifier object"
  end

  context "AuthorityKeyIdentifier" do
    before :all do
      @extension_value = "keyid:always"
    end

    it_should_behave_like "a correct R509 AuthorityKeyIdentifier object"
  end

  context "SubjectAlternativeName" do
    context "with a DNS alternative name only" do
      before :all do
        @dns_names = ["www.test.local"]
        @ip_addresses = []
        @uris = []
        @extension_value = "DNS:#{@dns_names.join(",DNS:")}"
      end

      it_should_behave_like "a correct R509 SubjectAlternativeName object"
    end

    context "with multiple DNS alternative names only" do
      before :all do
        @dns_names = ["www.test.local", "www2.test.local"]
        @ip_addresses = []
        @uris = []
        @extension_value = "DNS:#{@dns_names.join(",DNS:")}"
      end

      it_should_behave_like "a correct R509 SubjectAlternativeName object"
    end

    context "with an IP address alternative name only" do
      before :all do
        @dns_names = []
        @ip_addresses = ["10.1.2.3"]
        @uris = []
        @extension_value = "IP:#{@ip_addresses.join(",IP:")}"
      end

      it_should_behave_like "a correct R509 SubjectAlternativeName object"
    end

    context "with multiple IP address alternative names only" do
      before :all do
        @dns_names = []
        @ip_addresses = ["10.1.2.3", "10.1.2.4"]
        @uris = []
        @extension_value = "IP:#{@ip_addresses.join(",IP:")}"
      end

      it_should_behave_like "a correct R509 SubjectAlternativeName object"
    end

    context "with a URI alternative name only" do
      before :all do
        @dns_names = []
        @ip_addresses = []
        @uris = ["http://www.test.local"]
        @extension_value = "URI:#{@uris.join(",URI:")}"
      end

      it_should_behave_like "a correct R509 SubjectAlternativeName object"
    end

    context "with multiple URI alternative names only" do
      before :all do
        @dns_names = []
        @ip_addresses = []
        @uris = ["http://www.test.local","http://www2.test.local"]
        @extension_value = "URI:#{@uris.join(",URI:")}"
      end

      it_should_behave_like "a correct R509 SubjectAlternativeName object"
    end

    context "with multiple different alternative names" do
      before :all do
        @dns_names = ["www.test.local"]
        @ip_addresses = ["10.1.2.3"]
        @uris = ["http://www.test.local"]
        @extension_value = "DNS:#{@dns_names.join(",DNS:")},IP:#{@ip_addresses.join(",IP:")},URI:#{@uris.join(",URI:")}"
      end

      it_should_behave_like "a correct R509 SubjectAlternativeName object"
    end

    context "with multiple different alternative names with trailing newlines" do
      before :all do
        @dns_names = ["www.test.local"]
        @ip_addresses = ["10.1.2.3"]
        @uris = ["http://www.test.local"]
        @extension_value = "DNS:#{@dns_names.join("\n,DNS:")}\n,IP:#{@ip_addresses.join("\n,IP:")}\n,URI:#{@uris.join("\n,URI:")}\n"
      end

      it_should_behave_like "a correct R509 SubjectAlternativeName object"
    end
  end
  context "AuthorityInfoAccess" do
    context "with a CA Issuers URI only" do
      before :all do
        @ca_issuers_uris = ["http://www.test.local/ca.cert"]
        @ocsp_uris = []
        @extension_value = "CA Issuers - URI:#{@ca_issuers_uris.join(",URI:")}"
      end

      it_should_behave_like "a correct R509 AuthorityInfoAccess object"
    end

    context "with multiple CA Issuers URIs only" do
      before :all do
        @ca_issuers_uris = ["http://www.test.local/ca.cert", "http://www.test.local/subca.cert"]
        @ocsp_uris = []
        @extension_value = "CA Issuers - URI:#{@ca_issuers_uris.join(",CA Issuers - URI:")}"
      end

      it_should_behave_like "a correct R509 AuthorityInfoAccess object"
    end

    context "with an OCSP URI only" do
      before :all do
        @ca_issuers_uris = []
        @ocsp_uris = ["http://www.test.local"]
        @extension_value = "OCSP - URI:#{@ocsp_uris.join(",URI:")}"
      end

      it_should_behave_like "a correct R509 AuthorityInfoAccess object"
    end

    context "with multiple OCSP URIs only" do
      before :all do
        @ca_issuers_uris = []
        @ocsp_uris = ["http://www.test.local", "http://www2.test.local"]
        @extension_value = "OCSP - URI:#{@ocsp_uris.join(",OCSP - URI:")}"
      end

      it_should_behave_like "a correct R509 AuthorityInfoAccess object"
    end

    context "with both a CA Issuers URI and an OCSP URI" do
      before :all do
        @ca_issuers_uris = ["http://www.test.local/ca.cert"]
        @ocsp_uris = ["http://www.test.local"]
        @extension_value = "CA Issuers - URI:#{@ca_issuers_uris.join(",CA Issuers - URI:")},OCSP - URI:#{@ocsp_uris.join(",URI:")}"
      end

      it_should_behave_like "a correct R509 AuthorityInfoAccess object"
    end

    context "with both a CA Issuers URI and an OCSP URI with trailing newlines" do
      before :all do
        @ca_issuers_uris = ["http://www.test.local/ca.cert"]
        @ocsp_uris = ["http://www.test.local"]
        @extension_value = "CA Issuers - URI:#{@ca_issuers_uris.join("\n,CA Issuers - URI:")}\n,OCSP - URI:#{@ocsp_uris.join("\n,URI:")}\n"
      end

      it_should_behave_like "a correct R509 AuthorityInfoAccess object"
    end
  end

  context "CrlDistributionPoints" do
    context "with a single CRL URI" do
      before :all do
        @crl_uris = ["http://www.test.local/ca.crl"]
        @extension_value = "URI:#{@crl_uris.join(",URI:")}"
      end

      it_should_behave_like "a correct R509 CrlDistributionPoints object"
    end

    context "with multiple CRL URIs" do
      before :all do
        @crl_uris = ["http://www.test.local/ca.crl", "http://www.test.local/subca.crl"]
        @extension_value = "URI:#{@crl_uris.join(",URI:")}"
      end

      it_should_behave_like "a correct R509 CrlDistributionPoints object"
    end

    context "with multiple CRL URIs and trailing newlines" do
      before :all do
        @crl_uris = ["http://www.test.local/ca.crl", "http://www.test.local/subca.crl"]
        @extension_value = "URI:#{@crl_uris.join("\n,URI:")}\n"
      end

      it_should_behave_like "a correct R509 CrlDistributionPoints object"
    end
  end

  context "OCSPNoCheck" do
    it_should_behave_like "a correct R509 OCSPNoCheck object"
  end


end
