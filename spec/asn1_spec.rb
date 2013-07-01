require 'spec_helper'
require 'r509/asn1'

describe R509::ASN1 do
  it "does not error with valid extension on get_extension_payload" do
    #SAN extension
    der = "0L\u0006\u0003U\u001D\u0011\u0001\u0001\xFF\u0004B0@\x82\u000Ewww.test.local\x87\u0004\n\u0001\u0002\u0003\x86\u0015http://www.test.local\x81\u0011myemail@email.com"
    ext = OpenSSL::X509::Extension.new(der)
    payload = R509::ASN1.get_extension_payload(ext)
    payload.should_not be_nil
  end

  context "general_name_parser" do
    it "returns nil if passed nil" do
      general_names = R509::ASN1.general_name_parser(nil)
      general_names.should be_nil
    end
    it "when passed an existing generalname object, return the same object" do
      general_names = R509::ASN1::GeneralNames.new
      names = R509::ASN1.general_name_parser(general_names)
      names.should == general_names
    end
    it "correctly parses dns names" do
      general_names = R509::ASN1.general_name_parser(['domain2.com','domain3.com'])
      general_names.dns_names.should == ["domain2.com", "domain3.com"]
    end

    it "adds SAN IPv4 names" do
      general_names = R509::ASN1.general_name_parser(['1.2.3.4','2.3.4.5'])
      general_names.ip_addresses.should == ["1.2.3.4", "2.3.4.5"]
    end

    it "adds SAN IPv6 names" do
      general_names = R509::ASN1.general_name_parser(['FE80:0:0:0:0:0:0:1','fe80::2',])
      general_names.ip_addresses.should == ["fe80::1", "fe80::2"]
    end

    it "adds SAN URI names" do
      general_names = R509::ASN1.general_name_parser(['http://myuri.com','ftp://whyftp'])
      general_names.uris.should == ['http://myuri.com','ftp://whyftp']
    end

    it "adds SAN rfc822 names" do
      general_names = R509::ASN1.general_name_parser(['email@domain.com','some@other.com'])
      general_names.rfc_822_names.should == ['email@domain.com','some@other.com']
    end

    it "adds directoryNames via R509::Subject objects" do
      s = R509::Subject.new([['CN','what-what']])
      s2 = R509::Subject.new([['C','US'],['L','locality']])
      general_names = R509::ASN1.general_name_parser([s,s2])
      general_names.directory_names.size.should == 2
      general_names.directory_names[0].CN.should == 'what-what'
      general_names.directory_names[0].C.should be_nil
      general_names.directory_names[1].C.should == 'US'
      general_names.directory_names[1].L.should == 'locality'
    end

    it "adds directoryNames via arrays" do
      s = [['CN','what-what']]
      s2 = [['C','US'],['L','locality']]
      general_names = R509::ASN1.general_name_parser([s,s2])
      general_names.directory_names.size.should == 2
      general_names.directory_names[0].CN.should == 'what-what'
      general_names.directory_names[0].C.should be_nil
      general_names.directory_names[1].C.should == 'US'
      general_names.directory_names[1].L.should == 'locality'
    end

    it "adds a mix of SAN name types" do
      general_names = R509::ASN1.general_name_parser(['1.2.3.4','http://langui.sh','email@address.local','domain.internal','2.3.4.5'])
      general_names.ip_addresses.should == ['1.2.3.4','2.3.4.5']
      general_names.dns_names.should == ['domain.internal']
      general_names.uris.should == ['http://langui.sh']
      general_names.rfc_822_names.should == ['email@address.local']
    end

    it "handles empty array" do
      general_names = R509::ASN1.general_name_parser([])
      general_names.names.size.should == 0
    end

    it "errors on non-array" do
      expect { R509::ASN1.general_name_parser("string!") }.to raise_error(ArgumentError, "You must supply an array or existing R509::ASN1 GeneralNames object to general_name_parser")
    end

  end
end

describe R509::ASN1::GeneralName do
  context "parses types to tags within ::map_type_to_tag" do
    it "handles otherName" do
      R509::ASN1::GeneralName.map_type_to_tag(:otherName).should == 0
      R509::ASN1::GeneralName.map_type_to_tag("otherName").should == 0
    end
    it "handles rfc822Name" do
      R509::ASN1::GeneralName.map_type_to_tag(:rfc822Name).should == 1
      R509::ASN1::GeneralName.map_type_to_tag("rfc822Name").should == 1
      R509::ASN1::GeneralName.map_type_to_tag("email").should == 1
    end
    it "handles dNSName" do
      R509::ASN1::GeneralName.map_type_to_tag(:dNSName).should == 2
      R509::ASN1::GeneralName.map_type_to_tag("dNSName").should == 2
      R509::ASN1::GeneralName.map_type_to_tag("DNS").should == 2
    end
    it "handles x400Address" do
      R509::ASN1::GeneralName.map_type_to_tag(:x400Address).should == 3
      R509::ASN1::GeneralName.map_type_to_tag("x400Address").should == 3
    end
    it "handles directoryName" do
      R509::ASN1::GeneralName.map_type_to_tag(:directoryName).should == 4
      R509::ASN1::GeneralName.map_type_to_tag("directoryName").should == 4
      R509::ASN1::GeneralName.map_type_to_tag("dirName").should == 4
    end
    it "handles ediPartyName" do
      R509::ASN1::GeneralName.map_type_to_tag(:ediPartyName).should == 5
      R509::ASN1::GeneralName.map_type_to_tag("ediPartyName").should == 5
    end
    it "handles uniformResourceIdentifier" do
      R509::ASN1::GeneralName.map_type_to_tag(:uniformResourceIdentifier).should == 6
      R509::ASN1::GeneralName.map_type_to_tag("uniformResourceIdentifier").should == 6
      R509::ASN1::GeneralName.map_type_to_tag("URI").should == 6
    end
    it "handles iPAddress" do
      R509::ASN1::GeneralName.map_type_to_tag(:iPAddress).should == 7
      R509::ASN1::GeneralName.map_type_to_tag("iPAddress").should == 7
      R509::ASN1::GeneralName.map_type_to_tag("IP").should == 7
    end
    it "handles registeredID" do
      R509::ASN1::GeneralName.map_type_to_tag(:registeredID).should == 8
      R509::ASN1::GeneralName.map_type_to_tag("registeredID").should == 8
    end
  end
  context "::map_tag_to_type" do
    it "handles otherName" do
      R509::ASN1::GeneralName.map_tag_to_type(0).should == :otherName
    end
    it "handles rfc822Name" do
      R509::ASN1::GeneralName.map_tag_to_type(1).should == :rfc822Name
    end
    it "handles dNSName" do
      R509::ASN1::GeneralName.map_tag_to_type(2).should == :dNSName
    end
    it "handles x400Address" do
      R509::ASN1::GeneralName.map_tag_to_type(3).should == :x400Address
    end
    it "handles directoryName" do
      R509::ASN1::GeneralName.map_tag_to_type(4).should == :directoryName
    end
    it "handles ediPartyName" do
      R509::ASN1::GeneralName.map_tag_to_type(5).should == :ediPartyName
    end
    it "handles uniformResourceIdentifier" do
      R509::ASN1::GeneralName.map_tag_to_type(6).should == :uniformResourceIdentifier
    end
    it "handles iPAddress" do
      R509::ASN1::GeneralName.map_tag_to_type(7).should == :iPAddress
    end
    it "handles registeredID" do
      R509::ASN1::GeneralName.map_tag_to_type(8).should == :registeredID
    end
    it "raises error with invalid tag" do
      expect { R509::ASN1::GeneralName.map_tag_to_type(28) }.to raise_error(R509::R509Error,"Invalid tag 28")
    end

  end
  context "::map_tag_to_serial_prefix" do
    it "handles otherName" do
      expect { R509::ASN1::GeneralName.map_tag_to_serial_prefix(0) }.to raise_error(R509::R509Error)
    end
    it "handles rfc822Name" do
      R509::ASN1::GeneralName.map_tag_to_serial_prefix(1).should == "email"
    end
    it "handles dNSName" do
      R509::ASN1::GeneralName.map_tag_to_serial_prefix(2).should == "DNS"
    end
    it "handles x400Address" do
      expect { R509::ASN1::GeneralName.map_tag_to_serial_prefix(3) }.to raise_error(R509::R509Error)
    end
    it "handles directoryName" do
      R509::ASN1::GeneralName.map_tag_to_serial_prefix(4).should == "dirName"
    end
    it "handles ediPartyName" do
      expect { R509::ASN1::GeneralName.map_tag_to_serial_prefix(5) }.to raise_error(R509::R509Error)
    end
    it "handles uniformResourceIdentifier" do
      R509::ASN1::GeneralName.map_tag_to_serial_prefix(6).should == "URI"
    end
    it "handles iPAddress" do
      R509::ASN1::GeneralName.map_tag_to_serial_prefix(7).should == "IP"
    end
    it "handles registeredID" do
      expect { R509::ASN1::GeneralName.map_tag_to_serial_prefix(8) }.to raise_error(R509::R509Error)
    end
  end
  it "handles rfc822Name" do
    der = "\x81\u0011myemail@email.com"
    asn = OpenSSL::ASN1.decode der
    gn = R509::ASN1::GeneralName.new(asn)
    gn.type.should == :rfc822Name
    gn.value.should == 'myemail@email.com'
  end
  it "handles dNSName" do
    der = "\x82\u000Ewww.test.local"
    asn = OpenSSL::ASN1.decode der
    gn = R509::ASN1::GeneralName.new(asn)
    gn.type.should == :dNSName
    gn.value.should == 'www.test.local'
  end
  it "handles uniformResourceIdentifier" do
    der = "\x86\u001Fhttp://www.test.local/subca.crl"
    asn = OpenSSL::ASN1.decode der
    gn = R509::ASN1::GeneralName.new(asn)
    gn.type.should == :uniformResourceIdentifier
    gn.value.should == "http://www.test.local/subca.crl"
  end
  it "handles iPAddress v4" do
    der = "\x87\u0004\n\u0001\u0002\u0003"
    asn = OpenSSL::ASN1.decode der
    gn = R509::ASN1::GeneralName.new(asn)
    gn.type.should == :iPAddress
    gn.value.should == '10.1.2.3'
  end
  it "handles iPAddress v6" do
    der = "\x87\x10\x00\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    asn = OpenSSL::ASN1.decode der
    gn = R509::ASN1::GeneralName.new(asn)
    gn.type.should == :iPAddress
    gn.value.should == 'ff::'
  end
  it "handles iPAddress v4 with netmask" do
    der = "\x87\b\n\x01\x02\x03\xFF\xFF\xFF\xFF"
    asn = OpenSSL::ASN1.decode der
    gn = R509::ASN1::GeneralName.new(asn)
    gn.type.should == :iPAddress
    gn.value.should == '10.1.2.3/255.255.255.255'
  end
  it "handles iPAddress v6 with netmask" do
    der = "\x87 \x00\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\x00\xFF\x00\xFF\x00\xFF\x00\xFF\x00\xFF\x00\xFF\x00\xFF"
    asn = OpenSSL::ASN1.decode der
    gn = R509::ASN1::GeneralName.new(asn)
    gn.type.should == :iPAddress
    gn.value.should == 'ff::/ff:ff:ff:ff:ff:ff:ff:ff'
  end
  it "handles directoryName" do
    der = "\xA4`0^1\v0\t\u0006\u0003U\u0004\u0006\u0013\u0002US1\u00110\u000F\u0006\u0003U\u0004\b\f\bIllinois1\u00100\u000E\u0006\u0003U\u0004\a\f\aChicago1\u00180\u0016\u0006\u0003U\u0004\n\f\u000FRuby CA Project1\u00100\u000E\u0006\u0003U\u0004\u0003\f\aTest CA"
    asn = OpenSSL::ASN1.decode der
    gn = R509::ASN1::GeneralName.new(asn)
    gn.type.should == :directoryName
    gn.value.to_s.should == '/C=US/ST=Illinois/L=Chicago/O=Ruby CA Project/CN=Test CA'
  end
  it "errors on unimplemented type" do
    # otherName type
    der = "\xA0\u0014\u0006\u0003*\u0003\u0004\xA0\r\u0016\vHello World"
    asn = OpenSSL::ASN1.decode der
    expect { R509::ASN1::GeneralName.new(asn) }.to raise_error(R509::R509Error, "Unimplemented GeneralName tag: 0. At this time R509 does not support GeneralName types other than rfc822Name, dNSName, uniformResourceIdentifier, iPAddress, and directoryName")
  end
end

describe R509::ASN1::GeneralNames do
  it "adds items of allowed type to the object" do
    asn = OpenSSL::ASN1.decode "\x82\u000Ewww.test.local"
    asn2 = OpenSSL::ASN1.decode "\x81\u0011myemail@email.com"
    asn3 = OpenSSL::ASN1.decode "\x82\u000Ewww.text.local"
    gns = R509::ASN1::GeneralNames.new
    gns.add_item(asn)
    gns.add_item(asn2)
    gns.add_item(asn3)
    gns.dns_names.should == ["www.test.local","www.text.local"]
    gns.rfc_822_names.should == ["myemail@email.com"]
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
    gns.names.count.should == 3
    gns.names[0].type.should == :dNSName
    gns.names[0].value.should == "www.test.local"
    gns.names[1].type.should == :rfc822Name
    gns.names[1].value.should == "myemail@email.com"
    gns.names[2].type.should == :dNSName
    gns.names[2].value.should == "www.text.local"
  end

  it "allows #uniq-ing of #names" do
    gns = R509::ASN1::GeneralNames.new
    gns.create_item(:tag => 1, :value => "test")
    gns.create_item(:tag => 1, :value => "test")
    gns.names.count.should == 2
    gns.names.uniq.count.should == 1
  end

  it "errors with invalid params to #create_item" do
    gns = R509::ASN1::GeneralNames.new
    expect { gns.create_item({}) }.to raise_error(ArgumentError,'Must be a hash with (:tag or :type) and :value nodes')
  end

  it "allows addition of directoryNames with #create_item passing existing subject object" do
    gns = R509::ASN1::GeneralNames.new
    s = R509::Subject.new([['C','US'],['L','locality']])
    gns.directory_names.size.should == 0
    gns.create_item( :tag => 4, :value => s )
    gns.directory_names.size.should == 1
  end
  it "allows addition of directoryNames with #create_item passing array" do
    gns = R509::ASN1::GeneralNames.new
    gns.directory_names.size.should == 0
    gns.create_item( :tag => 4, :value => [['C','US'],['L','locality']] )
    gns.directory_names.size.should == 1
  end
end

describe R509::ASN1::PolicyInformation do
  it "loads data with a policy oid but no qualifiers" do
    data = OpenSSL::ASN1.decode "0\r\u0006\v`\x86H\u0001\xE09\u0001\u0002\u0003\u0004\u0001"
    pi = R509::ASN1::PolicyInformation.new(data)
    pi.policy_identifier.should == '2.16.840.1.12345.1.2.3.4.1'
    pi.policy_qualifiers.should be_nil
  end
  it "loads data with a policy oid and a single qualifier" do
    data = OpenSSL::ASN1.decode "0U\u0006\v`\x86H\u0001\xE09\u0001\u0002\u0003\u0004\u00010F0\"\u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u0001\u0016\u0016http://example.com/cps0 \u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u0001\u0016\u0014http://other.com/cps"
    pi = R509::ASN1::PolicyInformation.new(data)
    pi.policy_identifier.should == '2.16.840.1.12345.1.2.3.4.1'
    pi.policy_qualifiers.cps_uris.empty?.should == false
    pi.policy_qualifiers.user_notices.empty?.should == true
  end
  it "loads data with a policy oid and multiple qualifiers" do
    data = OpenSSL::ASN1.decode "0\x81\x94\u0006\n`\x86H\u0001\x86\x8D\u001F\u0015\x81k0\x81\x850#\u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u0001\u0016\u0017http://example.com/cps20;\u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u00020/0\u0018\u0016\vanother org0\t\u0002\u0001\u0003\u0002\u0001\u0002\u0002\u0001\u0001\u001A\u0013this is a bad thing0!\u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u00020\u0015\u001A\u0013another user notice"
    pi = R509::ASN1::PolicyInformation.new(data)
    pi.policy_identifier.should == '2.16.840.1.99999.21.235'
    pi.policy_qualifiers.cps_uris.empty?.should == false
    pi.policy_qualifiers.user_notices.empty?.should == false
  end
end

describe R509::ASN1::PolicyQualifiers do
  before :each do
    @pq = R509::ASN1::PolicyQualifiers.new
  end

  it "initializes empty cps_uris and user_notices" do
    @pq.should_not be_nil
    @pq.cps_uris.empty?.should == true
    @pq.user_notices.empty?.should == true
  end
  it "parses a cps qualifier and adds it to cps_uris" do
    data = OpenSSL::ASN1.decode "0#\u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u0001\u0016\u0017http://example.com/cps2"
    @pq.parse(data)
    @pq.cps_uris.should == ['http://example.com/cps2']
    @pq.user_notices.should == []
  end
  it "parses a user notice and adds it to user_notices" do
    data = OpenSSL::ASN1.decode "0!\u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u00020\u0015\u001A\u0013another user notice"
    @pq.parse(data)
    @pq.cps_uris.should == []
    @pq.user_notices.count.should == 1
  end
end

describe R509::ASN1::UserNotice do
  it "loads data with both a notice reference and explicit text" do
    data = OpenSSL::ASN1.decode "0\u001F0\u0016\u0016\u0006my org0\f\u0002\u0001\u0001\u0002\u0001\u0002\u0002\u0001\u0003\u0002\u0001\u0004\u001A\u0005thing"
    un = R509::ASN1::UserNotice.new(data)
    un.notice_reference.should_not be_nil
    un.explicit_text.should == 'thing'
  end
  it "loads data with a notice reference" do
    data = OpenSSL::ASN1.decode "0\u00180\u0016\u0016\u0006my org0\f\u0002\u0001\u0001\u0002\u0001\u0002\u0002\u0001\u0003\u0002\u0001\u0004"
    un = R509::ASN1::UserNotice.new(data)
    un.notice_reference.should_not be_nil
    un.explicit_text.should be_nil
  end
  it "loads data with an explicit text" do
    data = OpenSSL::ASN1.decode "0\a\u001A\u0005thing"
    un = R509::ASN1::UserNotice.new(data)
    un.notice_reference.should be_nil
    un.explicit_text.should == 'thing'
  end
end

describe R509::ASN1::NoticeReference do
  it "loads data with an org and no notice numbers" do
    data = OpenSSL::ASN1.decode "0\n\u0016\u0006my org0\u0000"
    nr = R509::ASN1::NoticeReference.new(data)
    nr.organization.should == 'my org'
    nr.notice_numbers.should == []
  end
  it "loads data with an org and 1 notice number" do
    data = OpenSSL::ASN1.decode "0\r\u0016\u0006my org0\u0003\u0002\u0001\u0001"
    nr = R509::ASN1::NoticeReference.new(data)
    nr.organization.should == 'my org'
    nr.notice_numbers.should == [1]
  end
  it "loads data with an org and more than 1 notice number" do
    data = OpenSSL::ASN1.decode "0\u0016\u0016\u0006my org0\f\u0002\u0001\u0001\u0002\u0001\u0002\u0002\u0001\u0003\u0002\u0001\u0004"
    nr = R509::ASN1::NoticeReference.new(data)
    nr.organization.should == 'my org'
    nr.notice_numbers.should == [1,2,3,4]
  end
end
