require 'spec_helper'

include R509::Cert::Extensions

shared_examples_for "a correct R509 CertificatePolicies object" do
  before :all do
    @r509_ext = R509::Cert::Extensions::CertificatePolicies.new(@policy_data)
  end

  it "should correctly parse the data" do
    expect(@r509_ext.policies.count).to eq(1)
    expect(@r509_ext.policies[0].policy_identifier).to eq("2.16.840.1.12345.1.2.3.4.1")
    expect(@r509_ext.policies[0].policy_qualifiers.cps_uris).to eq(["http://example.com/cps", "http://other.com/cps"])
  end
end

describe R509::Cert::Extensions::CertificatePolicies do
  include R509::Cert::Extensions

  context "validate certificate policy structure" do
    it "must be an array" do
      expect { CertificatePolicies.new(:value => "whatever") }.to raise_error(ArgumentError, 'Not a valid certificate policy structure. Must be an array of hashes')
    end

    it "require a policy identifier" do
      expect { CertificatePolicies.new(:value => [{ "stuff" => "thing" }]) }.to raise_error(ArgumentError, 'Each policy requires a policy identifier')
    end

    it "the cps uri must be array of strings" do
      expect { CertificatePolicies.new(:value => [{ :policy_identifier => "1.2.3.4.5", :cps_uris => "not an array" }]) }.to raise_error(ArgumentError, 'CPS URIs must be an array of strings')
    end

    it "user notices must be an array of hashes" do
      expect { CertificatePolicies.new(:value => [{ :policy_identifier => "1.2.3.4.5", :user_notices => "not an array" }]) }.to raise_error(ArgumentError, 'User notices must be an array of hashes')
    end

    it "org in user notice requires notice numbers" do
      expect { CertificatePolicies.new(:value => [{ :policy_identifier => "1.2.3.4.5", :user_notices => [{ :explicit_text => "explicit", :organization => "something" }] }]) }.to raise_error(ArgumentError, 'If you provide an organization you must provide notice numbers')
    end

    it "notice numbers in user notice requires org" do
      expect { CertificatePolicies.new(:value => [{ :policy_identifier => "1.2.3.4.5", :user_notices => [{ :explicit_text => "explicit", :notice_numbers => "1,2,3" }] }]) }.to raise_error(ArgumentError, 'If you provide notice numbers you must provide an organization')
    end
  end

  context "CertificatePolicies" do
    before :all do
      @policy_data = "0\x81\x90\x06\x03U\x1D \x04\x81\x880\x81\x850\x81\x82\x06\v`\x86H\x01\xE09\x01\x02\x03\x04\x010s0\"\x06\b+\x06\x01\x05\x05\a\x02\x01\x16\x16http://example.com/cps0 \x06\b+\x06\x01\x05\x05\a\x02\x01\x16\x14http://other.com/cps0+\x06\b+\x06\x01\x05\x05\a\x02\x020\x1F0\x16\x16\x06my org0\f\x02\x01\x01\x02\x01\x02\x02\x01\x03\x02\x01\x04\x1A\x05thing"
    end

    context "creation & yaml generation" do
      context "one policy" do
        before :all do
          @args = {
            :critical => false,
            :value => [
              {
                :policy_identifier => "2.16.840.1.12345.1.2.3.4.1",
                :cps_uris => ["http://example.com/cps", "http://other.com/cps"],
                :user_notices => [
                  {
                    :explicit_text => "thing",
                    :organization => "my org",
                    :notice_numbers => [1, 2, 3, 4]
                  }
                ]
              }
            ]
          }
          @cp = R509::Cert::Extensions::CertificatePolicies.new(@args)
        end

        it "creates extension" do
          expect(@cp).not_to be_nil
          expect(@cp.policies.count).to eq(1)
          expect(@cp.policies[0].policy_identifier).to eq("2.16.840.1.12345.1.2.3.4.1")
          expect(@cp.policies[0].policy_qualifiers.cps_uris).to eq(["http://example.com/cps", "http://other.com/cps"])
          expect(@cp.policies[0].policy_qualifiers.user_notices.count).to eq(1)
          un = @cp.policies[0].policy_qualifiers.user_notices[0]
          expect(un.notice_reference.notice_numbers).to eq([1, 2, 3, 4])
          expect(un.notice_reference.organization).to eq('my org')
          expect(un.explicit_text).to eq("thing")
        end

        it "builds yaml" do
          expect(YAML.load(@cp.to_yaml)).to eq(@args)
        end
      end

      context "multiple policies" do
        before :all do
          @args = {
            :critical => false,
            :value => [
              {
                :policy_identifier => "2.16.840.1.99999.21.234",
                :cps_uris => ["http://example.com/cps", "http://other.com/cps"],
                :user_notices => [{ :explicit_text => "this is a great thing", :organization => "my org", :notice_numbers => [1, 2, 3, 4] }]
              }, {
                :policy_identifier => "2.16.840.1.99999.21.235",
                :cps_uris => ["http://example.com/cps2"],
                :user_notices => [{ :explicit_text => "this is a bad thing", :organization => "another org", :notice_numbers => [3, 2, 1] }, { :explicit_text => "another user notice" }]
              },
              {
                :policy_identifier => "2.16.840.1.99999.0"
              }
            ]
          }
          @cp = R509::Cert::Extensions::CertificatePolicies.new(@args)
        end

        it "creates extension" do
          expect(@cp).not_to be_nil
          expect(@cp.policies.count).to eq(3)
          p0 = @cp.policies[0]
          expect(p0.policy_identifier).to eq("2.16.840.1.99999.21.234")
          expect(p0.policy_qualifiers.cps_uris).to eq(["http://example.com/cps", "http://other.com/cps"])
          expect(p0.policy_qualifiers.user_notices.count).to eq(1)
          un0 = p0.policy_qualifiers.user_notices[0]
          expect(un0.notice_reference.notice_numbers).to eq([1, 2, 3, 4])
          expect(un0.notice_reference.organization).to eq("my org")
          expect(un0.explicit_text).to eq("this is a great thing")
          p1 = @cp.policies[1]
          expect(p1.policy_identifier).to eq("2.16.840.1.99999.21.235")
          expect(p1.policy_qualifiers.cps_uris).to eq(["http://example.com/cps2"])
          expect(p1.policy_qualifiers.user_notices.count).to eq(2)
          un1 = p1.policy_qualifiers.user_notices[0]
          expect(un1.notice_reference.notice_numbers).to eq([3, 2, 1])
          expect(un1.notice_reference.organization).to eq("another org")
          expect(un1.explicit_text).to eq('this is a bad thing')
          un2 = p1.policy_qualifiers.user_notices[1]
          expect(un2.notice_reference).to be_nil
          expect(un2.explicit_text).to eq("another user notice")
          p2 = @cp.policies[2]
          expect(p2.policy_identifier).to eq("2.16.840.1.99999.0")
          expect(p2.policy_qualifiers).to be_nil
        end

        it "builds yaml" do
          expect(YAML.load(@cp.to_yaml)).to eq(@args)
        end
      end

      context "default criticality" do
        before :all do
          @args = { :value => [{ :policy_identifier => "2.16.840.1.12345.1.2.3.4.1" }] }
          @cp = R509::Cert::Extensions::CertificatePolicies.new(@args)
        end

        it "creates extension" do
          expect(@cp.critical?).to be false
        end

        it "builds yaml" do
          expect(YAML.load(@cp.to_yaml)).to eq(@args.merge(:critical => false))
        end
      end

      context "non-default criticality" do
        before :all do
          @args = { :value => [{ :policy_identifier => "2.16.840.1.12345.1.2.3.4.1" }], :critical => true }
          @cp = R509::Cert::Extensions::CertificatePolicies.new(@args)
        end

        it "creates extension" do
          expect(@cp.critical?).to be true
        end

        it "builds yaml" do
          expect(YAML.load(@cp.to_yaml)).to eq(@args)
        end
      end

    end

    it_should_behave_like "a correct R509 CertificatePolicies object"
  end

end

describe R509::Cert::Extensions::CertificatePolicies::PolicyInformation do
  it "loads data with a policy oid but no qualifiers" do
    data = OpenSSL::ASN1.decode "0\r\u0006\v`\x86H\u0001\xE09\u0001\u0002\u0003\u0004\u0001"
    pi = R509::Cert::Extensions::CertificatePolicies::PolicyInformation.new(data)
    expect(pi.policy_identifier).to eq('2.16.840.1.12345.1.2.3.4.1')
    expect(pi.policy_qualifiers).to be_nil
  end

  it "loads data with a policy oid and a single qualifier" do
    data = OpenSSL::ASN1.decode "0U\u0006\v`\x86H\u0001\xE09\u0001\u0002\u0003\u0004\u00010F0\"\u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u0001\u0016\u0016http://example.com/cps0 \u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u0001\u0016\u0014http://other.com/cps"
    pi = R509::Cert::Extensions::CertificatePolicies::PolicyInformation.new(data)
    expect(pi.policy_identifier).to eq('2.16.840.1.12345.1.2.3.4.1')
    expect(pi.policy_qualifiers.cps_uris.empty?).to eq(false)
    expect(pi.policy_qualifiers.user_notices.empty?).to eq(true)
  end

  it "loads data with a policy oid and multiple qualifiers" do
    data = OpenSSL::ASN1.decode "0\x81\x94\u0006\n`\x86H\u0001\x86\x8D\u001F\u0015\x81k0\x81\x850#\u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u0001\u0016\u0017http://example.com/cps20;\u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u00020/0\u0018\u0016\vanother org0\t\u0002\u0001\u0003\u0002\u0001\u0002\u0002\u0001\u0001\u001A\u0013this is a bad thing0!\u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u00020\u0015\u001A\u0013another user notice"
    pi = R509::Cert::Extensions::CertificatePolicies::PolicyInformation.new(data)
    expect(pi.policy_identifier).to eq('2.16.840.1.99999.21.235')
    expect(pi.policy_qualifiers.cps_uris.empty?).to eq(false)
    expect(pi.policy_qualifiers.user_notices.empty?).to eq(false)
  end

  it "builds yaml" do
    data = OpenSSL::ASN1.decode "0\x81\x94\u0006\n`\x86H\u0001\x86\x8D\u001F\u0015\x81k0\x81\x850#\u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u0001\u0016\u0017http://example.com/cps20;\u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u00020/0\u0018\u0016\vanother org0\t\u0002\u0001\u0003\u0002\u0001\u0002\u0002\u0001\u0001\u001A\u0013this is a bad thing0!\u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u00020\u0015\u001A\u0013another user notice"
    pi = R509::Cert::Extensions::CertificatePolicies::PolicyInformation.new(data)
    expect(YAML.load(pi.to_yaml)).to eq(:policy_identifier => "2.16.840.1.99999.21.235", :cps_uris => ["http://example.com/cps2"], :user_notices => [{ :explicit_text => "this is a bad thing", :organization => "another org", :notice_numbers => [3, 2, 1] }, { :explicit_text => "another user notice" }])
  end
end

describe R509::Cert::Extensions::CertificatePolicies::PolicyQualifiers do
  before :each do
    @pq = R509::Cert::Extensions::CertificatePolicies::PolicyQualifiers.new
  end

  it "initializes empty cps_uris and user_notices" do
    expect(@pq).not_to be_nil
    expect(@pq.cps_uris.empty?).to eq(true)
    expect(@pq.user_notices.empty?).to eq(true)
  end

  it "parses a cps qualifier and adds it to cps_uris" do
    data = OpenSSL::ASN1.decode "0#\u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u0001\u0016\u0017http://example.com/cps2"
    @pq.parse(data)
    expect(@pq.cps_uris).to eq(['http://example.com/cps2'])
    expect(@pq.user_notices).to eq([])
  end

  it "parses a user notice and adds it to user_notices" do
    data = OpenSSL::ASN1.decode "0!\u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u00020\u0015\u001A\u0013another user notice"
    @pq.parse(data)
    expect(@pq.cps_uris).to eq([])
    expect(@pq.user_notices.count).to eq(1)
  end

  it "builds yaml" do
    data = OpenSSL::ASN1.decode "0#\u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u0001\u0016\u0017http://example.com/cps2"
    @pq.parse(data)
    expect(YAML.load(@pq.to_yaml)).to eq(:cps_uris => ["http://example.com/cps2"])
  end
end

describe R509::Cert::Extensions::CertificatePolicies::UserNotice do
  it "loads data with both a notice reference and explicit text" do
    data = OpenSSL::ASN1.decode "0\u001F0\u0016\u0016\u0006my org0\f\u0002\u0001\u0001\u0002\u0001\u0002\u0002\u0001\u0003\u0002\u0001\u0004\u001A\u0005thing"
    un = R509::Cert::Extensions::CertificatePolicies::UserNotice.new(data)
    expect(un.notice_reference).not_to be_nil
    expect(un.explicit_text).to eq('thing')
  end

  it "loads data with a notice reference" do
    data = OpenSSL::ASN1.decode "0\u00180\u0016\u0016\u0006my org0\f\u0002\u0001\u0001\u0002\u0001\u0002\u0002\u0001\u0003\u0002\u0001\u0004"
    un = R509::Cert::Extensions::CertificatePolicies::UserNotice.new(data)
    expect(un.notice_reference).not_to be_nil
    expect(un.explicit_text).to be_nil
  end

  it "loads data with an explicit text" do
    data = OpenSSL::ASN1.decode "0\a\u001A\u0005thing"
    un = R509::Cert::Extensions::CertificatePolicies::UserNotice.new(data)
    expect(un.notice_reference).to be_nil
    expect(un.explicit_text).to eq('thing')
  end

  it "builds yaml" do
    data = OpenSSL::ASN1.decode "0\a\u001A\u0005thing"
    un = R509::Cert::Extensions::CertificatePolicies::UserNotice.new(data)
    expect(YAML.load(un.to_yaml)).to eq(:explicit_text => "thing")
  end
end

describe R509::Cert::Extensions::CertificatePolicies::NoticeReference do
  it "loads data with an org and no notice numbers" do
    data = OpenSSL::ASN1.decode "0\n\u0016\u0006my org0\u0000"
    nr = R509::Cert::Extensions::CertificatePolicies::NoticeReference.new(data)
    expect(nr.organization).to eq('my org')
    expect(nr.notice_numbers).to eq([])
  end

  it "loads data with an org and 1 notice number" do
    data = OpenSSL::ASN1.decode "0\r\u0016\u0006my org0\u0003\u0002\u0001\u0001"
    nr = R509::Cert::Extensions::CertificatePolicies::NoticeReference.new(data)
    expect(nr.organization).to eq('my org')
    expect(nr.notice_numbers).to eq([1])
  end

  it "loads data with an org and more than 1 notice number" do
    data = OpenSSL::ASN1.decode "0\u0016\u0016\u0006my org0\f\u0002\u0001\u0001\u0002\u0001\u0002\u0002\u0001\u0003\u0002\u0001\u0004"
    nr = R509::Cert::Extensions::CertificatePolicies::NoticeReference.new(data)
    expect(nr.organization).to eq('my org')
    expect(nr.notice_numbers).to eq([1, 2, 3, 4])
  end

  it "builds yaml" do
    data = OpenSSL::ASN1.decode "0\u0016\u0016\u0006my org0\f\u0002\u0001\u0001\u0002\u0001\u0002\u0002\u0001\u0003\u0002\u0001\u0004"
    nr = R509::Cert::Extensions::CertificatePolicies::NoticeReference.new(data)
    expect(YAML.load(nr.to_yaml)).to eq(:organization => "my org", :notice_numbers => [1, 2, 3, 4])
  end
end
