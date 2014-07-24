require 'spec_helper'

include R509::Cert::Extensions

shared_examples_for "a correct R509 CRLDistributionPoints object" do |critical|
  before :all do
    extension_name = "crlDistributionPoints"
    klass = CRLDistributionPoints
    ef = OpenSSL::X509::ExtensionFactory.new
    openssl_ext = ef.create_extension(extension_name, @extension_value, critical)
    @r509_ext = klass.new(openssl_ext)
  end

  it "crl_uri should be correct critical:#{critical}" do
    expect(@r509_ext.uris).to eq(@crl_uris)
  end

  it "reports #critical? properly" do
    expect(@r509_ext.critical?).to eq(critical)
  end
end

describe R509::Cert::Extensions::CRLDistributionPoints do
  include R509::Cert::Extensions

  context "validation" do
    it "raises an error if you pass a non-hash" do
      expect { CRLDistributionPoints.new("test") }.to raise_error(ArgumentError, 'You must pass a hash with a :value key')
    end

    it "raises an error if you pass a value that is not an array" do
      expect { CRLDistributionPoints.new(:value => "some-url") }.to raise_error(ArgumentError, 'crl_distribution_points must contain an array or R509::ASN1::GeneralNames object if provided')
    end

    it "raises an error if you pass an array that does not contain hashes" do
      expect { CRLDistributionPoints.new(:value => [{}, "string"]) }.to raise_error(ArgumentError, 'All elements of the array must be hashes with a :type and :value')
    end

    it "raises an error if you pass an array that does not contain both :type and :value" do
      expect { CRLDistributionPoints.new(:value => [{ :type => 'URI' }]) }.to raise_error(ArgumentError, 'All elements of the array must be hashes with a :type and :value')
      expect { CRLDistributionPoints.new(:value => [{ :value => 'value' }]) }.to raise_error(ArgumentError, 'All elements of the array must be hashes with a :type and :value')
    end
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
          expect(@cdp.rfc_822_names).to eq(['random string'])
        end

        it "builds yaml" do
          expect(YAML.load(@cdp.to_yaml)).to eq(:critical => false, :value => [{ :type => "email", :value => "random string" }])
        end
      end

      context "one CDP" do
        before :all do
          @args = { :value => [{ :type => 'URI', :value => 'http://crl.r509.org/ca.crl' }], :critical => false }
          @cdp = R509::Cert::Extensions::CRLDistributionPoints.new(@args)
        end

        it "creates extension" do
          expect(@cdp.uris).to eq(['http://crl.r509.org/ca.crl'])
        end

        it "builds yaml" do
          expect(YAML.load(@cdp.to_yaml)).to eq(@args)
        end
      end

      context "multiple CDP" do
        before :all do
          @args = { :value => [{ :type => 'URI', :value => 'http://crl.r509.org/ca.crl' }, { :type => 'dirName', :value => { :CN => 'myCN' } }], :critical => false }
          @cdp = R509::Cert::Extensions::CRLDistributionPoints.new(@args)
        end

        it "creates extension" do
          expect(@cdp.uris).to eq(['http://crl.r509.org/ca.crl'])
          expect(@cdp.directory_names[0].to_s).to eq('/CN=myCN')
        end

        it "builds yaml" do
          expect(YAML.load(@cdp.to_yaml)).to eq(@args)
        end
      end

      context "default criticality" do
        before :all do
          @args = { :value => [{ :type => "URI", :value => 'http://crl.r509.org/ca.crl' }] }
          @cdp = R509::Cert::Extensions::CRLDistributionPoints.new(@args)
        end

        it "creates extension" do
          expect(@cdp.critical?).to be false
        end

        it "builds yaml" do
          expect(YAML.load(@cdp.to_yaml)).to eq(@args.merge(:critical => false))
        end
      end

      context "non-default criticality" do
        before :all do
          @args = { :value => [{ :type => "URI", :value => 'http://crl.r509.org/ca.crl' }], :critical => true }
          @cdp = R509::Cert::Extensions::CRLDistributionPoints.new(@args)
        end

        it "creates extension" do
          expect(@cdp.critical?).to be true
        end

        it "builds yaml" do
          expect(YAML.load(@cdp.to_yaml)).to eq(@args)
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
