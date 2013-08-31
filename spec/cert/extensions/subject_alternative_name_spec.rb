require 'spec_helper'

include R509::Cert::Extensions

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

describe R509::Cert::Extensions::SubjectAlternativeName do
  include R509::Cert::Extensions


  context "validation" do
    it "errors when not supplying a hash" do
      expect {
        R509::Cert::Extensions::SubjectAlternativeName.new("create")
      }.to raise_error(ArgumentError,"You must supply a hash with a :value")
    end

    it "errors when not supplying :value" do
      expect {
        R509::Cert::Extensions::SubjectAlternativeName.new({})
      }.to raise_error(ArgumentError,"You must supply a hash with a :value")
    end
  end
  context "SubjectAlternativeName" do
    context "creation & yaml generation" do

      context "GeneralNames object" do
        before :all do
          gns = R509::ASN1::GeneralNames.new
          gns.create_item(:type => "rfc822Name", :value => "random string")
          @san = R509::Cert::Extensions::SubjectAlternativeName.new(:value => gns)
        end

        it "creates extension" do
          @san.rfc_822_names.should == ['random string']
        end

        it "builds yaml" do
          YAML.load(@san.to_yaml).should == {:critical=>false, :value=>[{:type=>"email", :value=>"random string"}]}
        end
      end

      context "single name" do
        before :all do
          @args = { :value => [{:type => "DNS", :value => 'domain.com' }], :critical => false }
          @san = R509::Cert::Extensions::SubjectAlternativeName.new(@args)
        end

        it "creates extension" do
          @san.dns_names.should == ['domain.com']
        end

        it "builds yaml" do
          @san.to_h.should == @args
        end
      end

      context "multiple names" do
        before :all do
          @args = { :value => [{:type => 'DNS', :value => 'domain.com' },{ :type => 'IP', :value => '127.0.0.1' }], :critical => false }
          @san = R509::Cert::Extensions::SubjectAlternativeName.new(@args)
        end
        it "creates extension" do
          @san.dns_names.should == ['domain.com']
          @san.ip_addresses.should == ['127.0.0.1']
        end

        it "builds yaml" do
          @san.to_h.should == @args
        end
      end

      context "default criticality" do
        before :all do
          @args = { :value => [{:type => "DNS", :value => 'domain.com' }] }
          @san = R509::Cert::Extensions::SubjectAlternativeName.new(@args)
        end

        it "creates extension" do
          @san.critical?.should be_false
        end

        it "builds yaml" do
          @san.to_h.should == @args.merge(:critical => false)
        end
      end

      context "creates with non-default criticality" do
        before :all do
          @args = { :value => [{:type => "DNS", :value => 'domain.com' }], :critical => true }
          @san = R509::Cert::Extensions::SubjectAlternativeName.new(@args)
        end

        it "creates extension" do
          @san.critical?.should be_true
        end

        it "builds yaml" do
          @san.to_h.should == @args
        end
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
end
