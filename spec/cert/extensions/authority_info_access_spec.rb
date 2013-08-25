require 'spec_helper'

include R509::Cert::Extensions

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

describe R509::Cert::Extensions do
  include R509::Cert::Extensions

  context "AuthorityInfoAccess" do
    context "creation & yaml generation" do
      context "using GeneralNames object" do
        before :all do
          gns = R509::ASN1::GeneralNames.new
          gns.create_item(:type => "rfc822Name", :value => "random string")
          gns.create_item(:type => "directoryName", :value => R509::Subject.new(:CN => "test", :O => "myOrg", :C => "US"))
          @aia = R509::Cert::Extensions::AuthorityInfoAccess.new(
            :ocsp_location => gns,
            :ca_issuers_location => gns
          )
        end

        it "creates extension" do
          @aia.ocsp.rfc_822_names.should == ['random string']
          @aia.ocsp.directory_names[0].to_s.should == '/CN=test/O=myOrg/C=US'
          @aia.ca_issuers.rfc_822_names.should == ['random string']
        end

        it "builds yaml" do
          YAML.load(@aia.to_yaml).should == {:critical=>false, :ocsp_location=>[{:type=>"email", :value=>"random string"}, {:type=>"dirName", :value=>{:CN=>"test", :O=>"myOrg", :C=>"US"}}], :ca_issuers_location=>[{:type=>"email", :value=>"random string"}, {:type=>"dirName", :value=>{:CN=>"test", :O=>"myOrg", :C=>"US"}}]}
        end
      end

      context "one OCSP location" do
        before :all do
          @args = { :ocsp_location => [{:type => "URI", :value => 'http://ocsp.domain.com' }], :critical => false }
          @aia = R509::Cert::Extensions::AuthorityInfoAccess.new(@args)
        end

        it "creates extension" do
          @aia.ocsp.uris.should == ['http://ocsp.domain.com']
        end

        it "builds yaml" do
          YAML.load(@aia.to_yaml).should == @args
        end
      end

      context " multiple OCSP locations" do
        before :all do
          @args = { :ocsp_location => [ { :type => 'URI', :value => 'http://ocsp.domain.com' }, { :type => "URI", :value => 'http://ocsp2.domain.com' }], :critical => false }
          @aia = R509::Cert::Extensions::AuthorityInfoAccess.new(@args)
        end

        it "creates extension" do
          @aia.ocsp.uris.should == ['http://ocsp.domain.com','http://ocsp2.domain.com']
        end

        it "builds yaml" do
          YAML.load(@aia.to_yaml).should == @args
        end
      end

      context "one caIssuers" do
        before :all do
          @args = { :ca_issuers_location => [ { :type => 'URI', :value => 'http://www.domain.com' } ], :critical => false }
          @aia = R509::Cert::Extensions::AuthorityInfoAccess.new(@args)
        end

        it "creates extension" do
          @aia.ca_issuers.uris.should == ['http://www.domain.com']
        end

        it "builds yaml" do
          YAML.load(@aia.to_yaml).should == @args
        end
      end

      context "multiple caIssuers" do
        before :all do
          @args = { :ca_issuers_location => [ { :type => 'URI', :value => 'http://www.domain.com' }, { :type => "URI", :value => 'http://www2.domain.com' }], :critical => false }
          @aia = R509::Cert::Extensions::AuthorityInfoAccess.new(@args)
        end

        it "creates extension" do
          @aia.ca_issuers.uris.should == ['http://www.domain.com','http://www2.domain.com']
        end

        it "builds yaml" do
          YAML.load(@aia.to_yaml).should == @args
        end
      end

      context "caIssuers+OCSP" do
        before :all do
          @args = { :ca_issuers_location => [{ :type => 'URI', :value => 'http://www.domain.com' }], :ocsp_location => [{ :type => 'URI', :value => 'http://ocsp.domain.com' }], :critical => false }
          @aia = R509::Cert::Extensions::AuthorityInfoAccess.new(@args)
        end

        it "creates extension" do
          @aia.ca_issuers.uris.should == ['http://www.domain.com']
          @aia.ocsp.uris.should == ['http://ocsp.domain.com']
        end

        it "builds yaml" do
          YAML.load(@aia.to_yaml).should == @args
        end
      end

      context "default criticality" do
        before :all do
        @args = { :ocsp_location => [{ :type => 'URI', :value => 'http://ocsp.domain.com' }]}
        @aia = R509::Cert::Extensions::AuthorityInfoAccess.new(@args)
        end

        it "creates extension" do
          @aia.critical?.should be_false
        end

        it "builds yaml" do
          YAML.load(@aia.to_yaml).should == @args.merge(:critical => false)
        end
      end

      context "non-default criticality" do
        before :all do
        @args = { :ocsp_location => [{ :type => 'URI', :value => 'http://ocsp.domain.com' }], :critical => true}
        @aia = R509::Cert::Extensions::AuthorityInfoAccess.new(@args)
        end

        it "creates extension" do
          @aia.critical?.should be_true
        end

        it "builds yaml" do
          YAML.load(@aia.to_yaml).should == @args
        end
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

end
