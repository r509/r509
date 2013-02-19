require 'spec_helper'
require 'r509/cert/extensions/cpobjects'

describe R509::Cert::Extensions::CPObjects::PolicyInformation do
  it "loads data with a policy oid but no qualifiers" do
    data = OpenSSL::ASN1.decode "0\r\u0006\v`\x86H\u0001\xE09\u0001\u0002\u0003\u0004\u0001"
    pi = R509::Cert::Extensions::CPObjects::PolicyInformation.new(data)
    pi.policy_identifier.should == '2.16.840.1.12345.1.2.3.4.1'
    pi.policy_qualifiers.should be_nil
  end
  it "loads data with a policy oid and a single qualifier" do
    data = OpenSSL::ASN1.decode "0U\u0006\v`\x86H\u0001\xE09\u0001\u0002\u0003\u0004\u00010F0\"\u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u0001\u0016\u0016http://example.com/cps0 \u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u0001\u0016\u0014http://other.com/cps"
    pi = R509::Cert::Extensions::CPObjects::PolicyInformation.new(data)
    pi.policy_identifier.should == '2.16.840.1.12345.1.2.3.4.1'
    pi.policy_qualifiers.cps_uris.empty?.should == false
    pi.policy_qualifiers.user_notices.empty?.should == true
  end
  it "loads data with a policy oid and multiple qualifiers" do
    data = OpenSSL::ASN1.decode "0\x81\x94\u0006\n`\x86H\u0001\x86\x8D\u001F\u0015\x81k0\x81\x850#\u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u0001\u0016\u0017http://example.com/cps20;\u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u00020/0\u0018\u0016\vanother org0\t\u0002\u0001\u0003\u0002\u0001\u0002\u0002\u0001\u0001\u001A\u0013this is a bad thing0!\u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u00020\u0015\u001A\u0013another user notice"
    pi = R509::Cert::Extensions::CPObjects::PolicyInformation.new(data)
    pi.policy_identifier.should == '2.16.840.1.99999.21.235'
    pi.policy_qualifiers.cps_uris.empty?.should == false
    pi.policy_qualifiers.user_notices.empty?.should == false
  end
end

describe R509::Cert::Extensions::CPObjects::PolicyQualifiers do
  before :each do
    @pq = R509::Cert::Extensions::CPObjects::PolicyQualifiers.new
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

describe R509::Cert::Extensions::CPObjects::UserNotice do
  it "loads data with both a notice reference and explicit text" do
    data = OpenSSL::ASN1.decode "0\u001F0\u0016\u0016\u0006my org0\f\u0002\u0001\u0001\u0002\u0001\u0002\u0002\u0001\u0003\u0002\u0001\u0004\u001A\u0005thing"
    un = R509::Cert::Extensions::CPObjects::UserNotice.new(data)
    un.notice_reference.should_not be_nil
    un.explicit_text.should == 'thing'
  end
  it "loads data with a notice reference" do
    data = OpenSSL::ASN1.decode "0\u00180\u0016\u0016\u0006my org0\f\u0002\u0001\u0001\u0002\u0001\u0002\u0002\u0001\u0003\u0002\u0001\u0004"
    un = R509::Cert::Extensions::CPObjects::UserNotice.new(data)
    un.notice_reference.should_not be_nil
    un.explicit_text.should be_nil
  end
  it "loads data with an explicit text" do
    data = OpenSSL::ASN1.decode "0\a\u001A\u0005thing"
    un = R509::Cert::Extensions::CPObjects::UserNotice.new(data)
    un.notice_reference.should be_nil
    un.explicit_text.should == 'thing'
  end
end

describe R509::Cert::Extensions::CPObjects::NoticeReference do
  it "loads data with an org and no notice numbers" do
    data = OpenSSL::ASN1.decode "0\n\u0016\u0006my org0\u0000"
    nr = R509::Cert::Extensions::CPObjects::NoticeReference.new(data)
    nr.organization.should == 'my org'
    nr.notice_numbers.should == []
  end
  it "loads data with an org and 1 notice number" do
    data = OpenSSL::ASN1.decode "0\r\u0016\u0006my org0\u0003\u0002\u0001\u0001"
    nr = R509::Cert::Extensions::CPObjects::NoticeReference.new(data)
    nr.organization.should == 'my org'
    nr.notice_numbers.should == [1]
  end
  it "loads data with an org and more than 1 notice number" do
    data = OpenSSL::ASN1.decode "0\u0016\u0016\u0006my org0\f\u0002\u0001\u0001\u0002\u0001\u0002\u0002\u0001\u0003\u0002\u0001\u0004"
    nr = R509::Cert::Extensions::CPObjects::NoticeReference.new(data)
    nr.organization.should == 'my org'
    nr.notice_numbers.should == [1,2,3,4]
  end
end
