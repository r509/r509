require 'spec_helper'

include R509::Cert::Extensions

shared_examples_for "a correct R509 CRLDistributionPoints object" do |critical|
  before :all do
    extension_name = "crlDistributionPoints"
    klass = CRLDistributionPoints
    ef = OpenSSL::X509::ExtensionFactory.new
    openssl_ext = ef.create_extension( extension_name, @extension_value , critical )
    @r509_ext = klass.new( openssl_ext )
  end

  it "crl_uri should be correct critical:#{critical}" do
    @r509_ext.uris.should == @crl_uris
  end

  it "reports #critical? properly" do
    @r509_ext.critical?.should == critical
  end
end

describe R509::Cert::Extensions::CRLDistributionPoints do
  include R509::Cert::Extensions

  it "raises an error if you pass a cdp_location that is not an array" do
    expect { CRLDistributionPoints.new( :value => "some-url" ) }.to raise_error(ArgumentError, 'cdp_location must be an array or R509::ASN1::GeneralNames object if provided')
  end

    it "raises an error if you pass an array that does not contain hashes" do
      expect { CRLDistributionPoints.new( :value => [{},"string"] ) }.to raise_error(ArgumentError, 'All elements of the array must be hashes with a :type and :value')
    end

    it "raises an error if you pass an array that does not contain both :type and :value" do
      expect { CRLDistributionPoints.new( :value => [{:type => 'URI'}] ) }.to raise_error(ArgumentError, 'All elements of the array must be hashes with a :type and :value')
      expect { CRLDistributionPoints.new( :value => [{:value => 'value'}] ) }.to raise_error(ArgumentError, 'All elements of the array must be hashes with a :type and :value')
    end


  context "CRLDistributionPoints" do
    context "creation & yaml generation" do
      context "GeneralNames object" do
        before :all do
          gns = R509::ASN1::GeneralNames.new
          gns.create_item(:type => "rfc822Name", :value => "random string")
          args = { :value => gns, :critical => false }
          @cdp = R509::Cert::Extensions::CRLDistributionPoints.new(args)
        end

        it "creates extension" do
          @cdp.rfc_822_names.should == ['random string']
        end

        it "builds yaml" do
          YAML.load(@cdp.to_yaml).should == {:critical=>false, :value=>[{:type=>"email", :value=>"random string"}]}
        end
      end

      context "one CDP" do
        before :all do
          @args = { :value => [{ :type => 'URI', :value => 'http://crl.r509.org/ca.crl'}], :critical => false }
          @cdp = R509::Cert::Extensions::CRLDistributionPoints.new(@args)
        end

        it "creates extension" do
          @cdp.uris.should == ['http://crl.r509.org/ca.crl']
        end

        it "builds yaml" do
          YAML.load(@cdp.to_yaml).should == @args
        end
      end

      context "multiple CDP" do
        before :all do
          @args = { :value => [{ :type => 'URI', :value => 'http://crl.r509.org/ca.crl' },{ :type => 'dirName', :value => {:CN => 'myCN'}}], :critical => false }
          @cdp = R509::Cert::Extensions::CRLDistributionPoints.new(@args)
        end

        it "creates extension" do
          @cdp.uris.should == ['http://crl.r509.org/ca.crl']
          @cdp.directory_names[0].to_s.should == '/CN=myCN'
        end

        it "builds yaml" do
          YAML.load(@cdp.to_yaml).should == @args
        end
      end

      context "default criticality" do
        before :all do
          @args = { :value => [{:type => "URI", :value => 'http://crl.r509.org/ca.crl'}] }
          @cdp = R509::Cert::Extensions::CRLDistributionPoints.new(@args)
        end

        it "creates extension" do
          @cdp.critical?.should be_false
        end

        it "builds yaml" do
          YAML.load(@cdp.to_yaml).should == @args.merge(:critical => false)
        end
      end

      context "non-default criticality" do
        before :all do
          @args = { :value => [{:type => "URI", :value => 'http://crl.r509.org/ca.crl'}], :critical => true }
          @cdp = R509::Cert::Extensions::CRLDistributionPoints.new(@args)
        end

        it "creates extension" do
          @cdp.critical?.should be_true
        end

        it "builds yaml" do
          YAML.load(@cdp.to_yaml).should == @args
        end
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

end
