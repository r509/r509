require 'spec_helper'
require 'r509/asn1'

describe R509::ASN1 do
  it "does not error with valid extension on get_extension_payload" do
    # SAN extension
    der = "0L\u0006\u0003U\u001D\u0011\u0001\u0001\xFF\u0004B0@\x82\u000Ewww.test.local\x87\u0004\n\u0001\u0002\u0003\x86\u0015http://www.test.local\x81\u0011myemail@email.com"
    ext = OpenSSL::X509::Extension.new(der)
    payload = R509::ASN1.get_extension_payload(ext)
    expect(payload).not_to be_nil
  end

  context "general_name_parser" do
    it "returns nil if passed nil" do
      general_names = R509::ASN1.general_name_parser(nil)
      expect(general_names).to be_nil
    end
    it "when passed an existing generalname object, return the same object" do
      general_names = R509::ASN1::GeneralNames.new
      names = R509::ASN1.general_name_parser(general_names)
      expect(names).to eq(general_names)
    end
    it "correctly parses dns names" do
      general_names = R509::ASN1.general_name_parser(['domain2.com', 'domain3.com'])
      expect(general_names.dns_names).to eq(["domain2.com", "domain3.com"])
    end

    it "adds SAN IPv4 names" do
      general_names = R509::ASN1.general_name_parser(['1.2.3.4', '2.3.4.5'])
      expect(general_names.ip_addresses).to eq(["1.2.3.4", "2.3.4.5"])
    end

    it "adds SAN IPv6 names" do
      general_names = R509::ASN1.general_name_parser(['FE80:0:0:0:0:0:0:1', 'fe80::2'])
      expect(general_names.ip_addresses).to eq(["fe80::1", "fe80::2"])
    end

    it "adds SAN URI names" do
      general_names = R509::ASN1.general_name_parser(['http://myuri.com', 'ftp://whyftp'])
      expect(general_names.uris).to eq(['http://myuri.com', 'ftp://whyftp'])
    end

    it "adds SAN rfc822 names" do
      general_names = R509::ASN1.general_name_parser(['email@domain.com', 'some@other.com'])
      expect(general_names.rfc_822_names).to eq(['email@domain.com', 'some@other.com'])
    end

    it "adds directoryNames via R509::Subject objects" do
      s = R509::Subject.new([['CN', 'what-what']])
      s2 = R509::Subject.new([['C', 'US'], ['L', 'locality']])
      general_names = R509::ASN1.general_name_parser([s, s2])
      expect(general_names.directory_names.size).to eq(2)
      expect(general_names.directory_names[0].CN).to eq('what-what')
      expect(general_names.directory_names[0].C).to be_nil
      expect(general_names.directory_names[1].C).to eq('US')
      expect(general_names.directory_names[1].L).to eq('locality')
    end

    it "adds directoryNames via arrays" do
      s = [['CN', 'what-what']]
      s2 = [['C', 'US'], ['L', 'locality']]
      general_names = R509::ASN1.general_name_parser([s, s2])
      expect(general_names.directory_names.size).to eq(2)
      expect(general_names.directory_names[0].CN).to eq('what-what')
      expect(general_names.directory_names[0].C).to be_nil
      expect(general_names.directory_names[1].C).to eq('US')
      expect(general_names.directory_names[1].L).to eq('locality')
    end

    it "adds a mix of SAN name types" do
      general_names = R509::ASN1.general_name_parser(['1.2.3.4', 'http://langui.sh', 'email@address.local', 'domain.internal', '2.3.4.5'])
      expect(general_names.ip_addresses).to eq(['1.2.3.4', '2.3.4.5'])
      expect(general_names.dns_names).to eq(['domain.internal'])
      expect(general_names.uris).to eq(['http://langui.sh'])
      expect(general_names.rfc_822_names).to eq(['email@address.local'])
    end

    it "handles empty array" do
      general_names = R509::ASN1.general_name_parser([])
      expect(general_names.names.size).to eq(0)
    end

    it "errors on non-array" do
      expect { R509::ASN1.general_name_parser("string!") }.to raise_error(ArgumentError, "You must supply an array or existing R509::ASN1 GeneralNames object to general_name_parser")
    end

  end
end

describe R509::ASN1::GeneralName do
  context "parses types to tags within ::map_type_to_tag" do
    it "handles otherName" do
      expect(R509::ASN1::GeneralName.map_type_to_tag(:otherName)).to eq(0)
      expect(R509::ASN1::GeneralName.map_type_to_tag("otherName")).to eq(0)
    end
    it "handles rfc822Name" do
      expect(R509::ASN1::GeneralName.map_type_to_tag(:rfc822Name)).to eq(1)
      expect(R509::ASN1::GeneralName.map_type_to_tag("rfc822Name")).to eq(1)
      expect(R509::ASN1::GeneralName.map_type_to_tag("email")).to eq(1)
    end
    it "handles dNSName" do
      expect(R509::ASN1::GeneralName.map_type_to_tag(:dNSName)).to eq(2)
      expect(R509::ASN1::GeneralName.map_type_to_tag("dNSName")).to eq(2)
      expect(R509::ASN1::GeneralName.map_type_to_tag("DNS")).to eq(2)
    end
    it "handles x400Address" do
      expect(R509::ASN1::GeneralName.map_type_to_tag(:x400Address)).to eq(3)
      expect(R509::ASN1::GeneralName.map_type_to_tag("x400Address")).to eq(3)
    end
    it "handles directoryName" do
      expect(R509::ASN1::GeneralName.map_type_to_tag(:directoryName)).to eq(4)
      expect(R509::ASN1::GeneralName.map_type_to_tag("directoryName")).to eq(4)
      expect(R509::ASN1::GeneralName.map_type_to_tag("dirName")).to eq(4)
    end
    it "handles ediPartyName" do
      expect(R509::ASN1::GeneralName.map_type_to_tag(:ediPartyName)).to eq(5)
      expect(R509::ASN1::GeneralName.map_type_to_tag("ediPartyName")).to eq(5)
    end
    it "handles uniformResourceIdentifier" do
      expect(R509::ASN1::GeneralName.map_type_to_tag(:uniformResourceIdentifier)).to eq(6)
      expect(R509::ASN1::GeneralName.map_type_to_tag("uniformResourceIdentifier")).to eq(6)
      expect(R509::ASN1::GeneralName.map_type_to_tag("URI")).to eq(6)
    end
    it "handles iPAddress" do
      expect(R509::ASN1::GeneralName.map_type_to_tag(:iPAddress)).to eq(7)
      expect(R509::ASN1::GeneralName.map_type_to_tag("iPAddress")).to eq(7)
      expect(R509::ASN1::GeneralName.map_type_to_tag("IP")).to eq(7)
    end
    it "handles registeredID" do
      expect(R509::ASN1::GeneralName.map_type_to_tag(:registeredID)).to eq(8)
      expect(R509::ASN1::GeneralName.map_type_to_tag("registeredID")).to eq(8)
    end
  end
  context "::map_tag_to_type" do
    it "handles otherName" do
      expect(R509::ASN1::GeneralName.map_tag_to_type(0)).to eq(:otherName)
    end
    it "handles rfc822Name" do
      expect(R509::ASN1::GeneralName.map_tag_to_type(1)).to eq(:rfc822Name)
    end
    it "handles dNSName" do
      expect(R509::ASN1::GeneralName.map_tag_to_type(2)).to eq(:dNSName)
    end
    it "handles x400Address" do
      expect(R509::ASN1::GeneralName.map_tag_to_type(3)).to eq(:x400Address)
    end
    it "handles directoryName" do
      expect(R509::ASN1::GeneralName.map_tag_to_type(4)).to eq(:directoryName)
    end
    it "handles ediPartyName" do
      expect(R509::ASN1::GeneralName.map_tag_to_type(5)).to eq(:ediPartyName)
    end
    it "handles uniformResourceIdentifier" do
      expect(R509::ASN1::GeneralName.map_tag_to_type(6)).to eq(:uniformResourceIdentifier)
    end
    it "handles iPAddress" do
      expect(R509::ASN1::GeneralName.map_tag_to_type(7)).to eq(:iPAddress)
    end
    it "handles registeredID" do
      expect(R509::ASN1::GeneralName.map_tag_to_type(8)).to eq(:registeredID)
    end
    it "raises error with invalid tag" do
      expect { R509::ASN1::GeneralName.map_tag_to_type(28) }.to raise_error(R509::R509Error, "Invalid tag 28")
    end

  end
  context ":map_tag_to_short_type" do
    it "handles otherName" do
      expect { R509::ASN1::GeneralName.map_tag_to_short_type(0) }.to raise_error(R509::R509Error)
    end
    it "handles rfc822Name" do
      expect(R509::ASN1::GeneralName.map_tag_to_short_type(1)).to eq("email")
    end
    it "handles dNSName" do
      expect(R509::ASN1::GeneralName.map_tag_to_short_type(2)).to eq("DNS")
    end
    it "handles x400Address" do
      expect { R509::ASN1::GeneralName.map_tag_to_short_type(3) }.to raise_error(R509::R509Error)
    end
    it "handles directoryName" do
      expect(R509::ASN1::GeneralName.map_tag_to_short_type(4)).to eq("dirName")
    end
    it "handles ediPartyName" do
      expect { R509::ASN1::GeneralName.map_tag_to_short_type(5) }.to raise_error(R509::R509Error)
    end
    it "handles uniformResourceIdentifier" do
      expect(R509::ASN1::GeneralName.map_tag_to_short_type(6)).to eq("URI")
    end
    it "handles iPAddress" do
      expect(R509::ASN1::GeneralName.map_tag_to_short_type(7)).to eq("IP")
    end
    it "handles registeredID" do
      expect { R509::ASN1::GeneralName.map_tag_to_short_type(8) }.to raise_error(R509::R509Error)
    end
  end

  context "creation & building hash" do
    it "errors on unimplemented types" do
      expect { R509::ASN1::GeneralName.new(:type => 0) }.to raise_error(R509::R509Error)
      expect { R509::ASN1::GeneralName.new(:type => 3) }.to raise_error(R509::R509Error)
      expect { R509::ASN1::GeneralName.new(:type => 5) }.to raise_error(R509::R509Error)
      expect { R509::ASN1::GeneralName.new(:type => 8) }.to raise_error(R509::R509Error)
    end
    context "email" do
      before :all do
        @args = { :type => 'email', :value => 'email@email.com' }
        @gn = R509::ASN1::GeneralName.new(@args)
      end

      it "creates object" do
        expect(@gn.type).to eq(:rfc822Name)
        expect(@gn.value).to eq('email@email.com')
        expect(@gn.tag).to eq(1)
      end

      it "builds hash" do
        expect(@gn.to_h).to eq(@args)
      end
    end
    context " DNS" do
      before :all do
        @args = { :type => 'DNS', :value => 'r509.org' }
        @gn = R509::ASN1::GeneralName.new(@args)
      end

      it "creates object" do
        expect(@gn.type).to eq(:dNSName)
        expect(@gn.value).to eq('r509.org')
        expect(@gn.tag).to eq(2)
      end

      it "builds hash" do
        expect(@gn.to_h).to eq(@args)
      end
    end
    context "dirName" do
      before :all do
        @args = { :type => 'dirName', :value => { :CN => 'test' } }
        @gn = R509::ASN1::GeneralName.new(@args)
      end

      it "creates object" do
        expect(@gn.type).to eq(:directoryName)
        expect(@gn.tag).to eq(4)
        expect(@gn.value.to_s).to eq('/CN=test')
      end

      it "builds hash" do
        expect(@gn.to_h).to eq(@args)
      end
    end
    context "URI" do
      before :all do
        @args = { :type => 'URI', :value => 'http://test.local' }
        @gn = R509::ASN1::GeneralName.new(@args)
      end

      it "creates object" do
        expect(@gn.type).to eq(:uniformResourceIdentifier)
        expect(@gn.value).to eq('http://test.local')
        expect(@gn.tag).to eq(6)
      end

      it "builds hash" do
        expect(@gn.to_h).to eq(@args)
      end
    end
    context "IPv4" do
      before :all do
        @args = { :type => 'IP', :value => '127.0.0.1' }
        @gn = R509::ASN1::GeneralName.new(@args)
      end

      it "creates object" do
        expect(@gn.type).to eq(:iPAddress)
        expect(@gn.value).to eq('127.0.0.1')
        expect(@gn.tag).to eq(7)
      end

      it "builds hash" do
        expect(@gn.to_h).to eq(@args)
      end
    end
    context "IPv4 with netmask" do
      before :all do
        @args = { :type => 'IP', :value => '127.0.0.1/255.255.252.0' }
        @gn = R509::ASN1::GeneralName.new(@args)
      end

      it "creates object" do
        expect(@gn.type).to eq(:iPAddress)
        expect(@gn.value).to eq('127.0.0.1/255.255.252.0')
        expect(@gn.tag).to eq(7)
      end

      it "builds hash" do
        expect(@gn.to_h).to eq(@args)
      end
    end
    context "IPv6" do
      before :all do
        @args = { :type => 'IP', :value => 'ff::ee' }
        @gn = R509::ASN1::GeneralName.new(@args)
      end

      it "creates object" do
        expect(@gn.type).to eq(:iPAddress)
        expect(@gn.value).to eq('ff::ee')
        expect(@gn.tag).to eq(7)
      end

      it "builds hash" do
        expect(@gn.to_h).to eq(@args)
      end
    end
    context "IPv6 with netmask" do
      before :all do
        @args = { :type => 'IP', :value => 'ff::ee/ff::' }
        @gn = R509::ASN1::GeneralName.new(@args)
      end

      it "creates object" do
        expect(@gn.type).to eq(:iPAddress)
        expect(@gn.value).to eq('ff::ee/ff::')
        expect(@gn.tag).to eq(7)
      end

      it "builds hash" do
        expect(@gn.to_h).to eq(@args)
      end
    end
  end

  it "handles rfc822Name" do
    der = "\x81\u0011myemail@email.com"
    asn = OpenSSL::ASN1.decode der
    gn = R509::ASN1::GeneralName.new(asn)
    expect(gn.type).to eq(:rfc822Name)
    expect(gn.value).to eq('myemail@email.com')
  end
  it "handles dNSName" do
    der = "\x82\u000Ewww.test.local"
    asn = OpenSSL::ASN1.decode der
    gn = R509::ASN1::GeneralName.new(asn)
    expect(gn.type).to eq(:dNSName)
    expect(gn.value).to eq('www.test.local')
  end
  it "handles uniformResourceIdentifier" do
    der = "\x86\u001Fhttp://www.test.local/subca.crl"
    asn = OpenSSL::ASN1.decode der
    gn = R509::ASN1::GeneralName.new(asn)
    expect(gn.type).to eq(:uniformResourceIdentifier)
    expect(gn.value).to eq("http://www.test.local/subca.crl")
  end
  it "handles iPAddress v4" do
    der = "\x87\u0004\n\u0001\u0002\u0003"
    asn = OpenSSL::ASN1.decode der
    gn = R509::ASN1::GeneralName.new(asn)
    expect(gn.type).to eq(:iPAddress)
    expect(gn.value).to eq('10.1.2.3')
  end
  it "handles iPAddress v6" do
    der = "\x87\x10\x00\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    asn = OpenSSL::ASN1.decode der
    gn = R509::ASN1::GeneralName.new(asn)
    expect(gn.type).to eq(:iPAddress)
    expect(gn.value).to eq('ff::')
  end
  it "handles iPAddress v4 with netmask" do
    der = "\x87\b\n\x01\x02\x03\xFF\xFF\xFF\xFF"
    asn = OpenSSL::ASN1.decode der
    gn = R509::ASN1::GeneralName.new(asn)
    expect(gn.type).to eq(:iPAddress)
    expect(gn.value).to eq('10.1.2.3/255.255.255.255')
  end
  it "handles iPAddress v6 with netmask" do
    der = "\x87 \x00\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\x00\xFF\x00\xFF\x00\xFF\x00\xFF\x00\xFF\x00\xFF\x00\xFF"
    asn = OpenSSL::ASN1.decode der
    gn = R509::ASN1::GeneralName.new(asn)
    expect(gn.type).to eq(:iPAddress)
    expect(gn.value).to eq('ff::/ff:ff:ff:ff:ff:ff:ff:ff')
  end
  it "handles directoryName" do
    der = "\xA4`0^1\v0\t\u0006\u0003U\u0004\u0006\u0013\u0002US1\u00110\u000F\u0006\u0003U\u0004\b\f\bIllinois1\u00100\u000E\u0006\u0003U\u0004\a\f\aChicago1\u00180\u0016\u0006\u0003U\u0004\n\f\u000FRuby CA Project1\u00100\u000E\u0006\u0003U\u0004\u0003\f\aTest CA"
    asn = OpenSSL::ASN1.decode der
    gn = R509::ASN1::GeneralName.new(asn)
    expect(gn.type).to eq(:directoryName)
    expect(gn.value.to_s).to eq('/C=US/ST=Illinois/L=Chicago/O=Ruby CA Project/CN=Test CA')
  end
  it "errors on unimplemented type" do
    # otherName type
    der = "\xA0\u0014\u0006\u0003*\u0003\u0004\xA0\r\u0016\vHello World"
    asn = OpenSSL::ASN1.decode der
    expect { R509::ASN1::GeneralName.new(asn) }.to raise_error(R509::R509Error, "Unimplemented GeneralName tag: 0. At this time R509 does not support GeneralName types other than rfc822Name, dNSName, uniformResourceIdentifier, iPAddress, and directoryName")
  end
end

describe R509::ASN1::GeneralNames do
  context "constructor" do
    it "creates an empty object when passed nil" do
      gns = R509::ASN1::GeneralNames.new
      expect(gns).not_to be_nil
    end
    it "builds a GeneralNames object when passed an array of GeneralName hashes" do
      gns = R509::ASN1::GeneralNames.new
      gns.create_item(:type => 'DNS', :value => 'domain.com')
      gns_new = R509::ASN1::GeneralNames.new(gns)
      expect(gns_new.names.size).to eq(1)
      expect(gns_new.dns_names.size).to eq(1)
      expect(gns_new.names).to eq(gns.names)
    end
  end
  it "adds items of allowed type to the object" do
    asn = OpenSSL::ASN1.decode "\x82\u000Ewww.test.local"
    asn2 = OpenSSL::ASN1.decode "\x81\u0011myemail@email.com"
    asn3 = OpenSSL::ASN1.decode "\x82\u000Ewww.text.local"
    gns = R509::ASN1::GeneralNames.new
    gns.add_item(asn)
    gns.add_item(asn2)
    gns.add_item(asn3)
    expect(gns.dns_names).to eq(["www.test.local", "www.text.local"])
    expect(gns.rfc_822_names).to eq(["myemail@email.com"])
  end
  it "errors on unimplemented type" do
    # otherName type
    gns = R509::ASN1::GeneralNames.new
    der = "\xA0\u0014\u0006\u0003*\u0003\u0004\xA0\r\u0016\vHello World"
    asn = OpenSSL::ASN1.decode der
    expect { gns.add_item(asn) }.to raise_error(R509::R509Error, "Unimplemented GeneralName tag: 0. At this time R509 does not support GeneralName types other than rfc822Name, dNSName, uniformResourceIdentifier, iPAddress, and directoryName")
  end
  it "preserves order" do
    asn = OpenSSL::ASN1.decode "\x82\u000Ewww.test.local"
    asn2 = OpenSSL::ASN1.decode "\x81\u0011myemail@email.com"
    asn3 = OpenSSL::ASN1.decode "\x82\u000Ewww.text.local"
    gns = R509::ASN1::GeneralNames.new
    gns.add_item(asn)
    gns.add_item(asn2)
    gns.add_item(asn3)
    expect(gns.names.count).to eq(3)
    expect(gns.names[0].type).to eq(:dNSName)
    expect(gns.names[0].value).to eq("www.test.local")
    expect(gns.names[1].type).to eq(:rfc822Name)
    expect(gns.names[1].value).to eq("myemail@email.com")
    expect(gns.names[2].type).to eq(:dNSName)
    expect(gns.names[2].value).to eq("www.text.local")
  end

  it "allows #uniq-ing of #names" do
    gns = R509::ASN1::GeneralNames.new
    gns.create_item(:tag => 1, :value => "test")
    gns.create_item(:tag => 1, :value => "test")
    expect(gns.names.count).to eq(2)
    expect(gns.names.uniq.count).to eq(1)
  end

  it "errors with invalid params to #create_item" do
    gns = R509::ASN1::GeneralNames.new
    expect { gns.create_item({}) }.to raise_error(ArgumentError, 'Must be a hash with (:tag or :type) and :value nodes')
  end

  it "allows addition of directoryNames with #create_item passing existing subject object" do
    gns = R509::ASN1::GeneralNames.new
    s = R509::Subject.new([['C', 'US'], ['L', 'locality']])
    expect(gns.directory_names.size).to eq(0)
    gns.create_item(:tag => 4, :value => s)
    expect(gns.directory_names.size).to eq(1)
  end
  it "allows addition of directoryNames with #create_item passing array" do
    gns = R509::ASN1::GeneralNames.new
    expect(gns.directory_names.size).to eq(0)
    gns.create_item(:tag => 4, :value => [['C', 'US'], ['L', 'locality']])
    expect(gns.directory_names.size).to eq(1)
  end
end
