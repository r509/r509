require 'spec_helper'

include R509::Cert::Extensions

shared_examples_for "a correct R509 CertificatePolicies object" do
  before :all do
    @r509_ext = R509::Cert::Extensions::CertificatePolicies.new(@policy_data)
  end

  it "should correctly parse the data" do
    @r509_ext.policies.count.should == 1
    @r509_ext.policies[0].policy_identifier.should == "2.16.840.1.12345.1.2.3.4.1"
    @r509_ext.policies[0].policy_qualifiers.cps_uris.should == ["http://example.com/cps", "http://other.com/cps"]
  end
end

describe R509::Cert::Extensions::CertificatePolicies do
  include R509::Cert::Extensions

  context "validate certificate policy structure" do
    it "must be an array" do
      expect { CertificatePolicies.new(:value => "whatever") }.to raise_error(ArgumentError,'Not a valid certificate policy structure. Must be an array of hashes')
    end

    it "require a policy identifier" do
      expect { CertificatePolicies.new(:value => [{"stuff" => "thing"}]) }.to raise_error(ArgumentError,'Each policy requires a policy identifier')
    end

    it "the cps uri must be array of strings" do
      expect { CertificatePolicies.new(:value => [{:policy_identifier => "1.2.3.4.5", :cps_uris => "not an array"}]) }.to raise_error(ArgumentError,'CPS URIs must be an array of strings')
    end

    it "user notices must be an array of hashes" do
      expect { CertificatePolicies.new(:value => [{:policy_identifier => "1.2.3.4.5", :user_notices => "not an array"}]) }.to raise_error(ArgumentError,'User notices must be an array of hashes')
    end

    it "org in user notice requires notice numbers" do
      expect { CertificatePolicies.new(:value => [{:policy_identifier => "1.2.3.4.5", :user_notices => [{:explicit_text => "explicit", :organization => "something"}]}]) }.to raise_error(ArgumentError,'If you provide an organization you must provide notice numbers')
    end

    it "notice numbers in user notice requires org" do
      expect { CertificatePolicies.new(:value => [{:policy_identifier => "1.2.3.4.5", :user_notices => [{:explicit_text => "explicit", :notice_numbers => "1,2,3"}]}]) }.to raise_error(ArgumentError,'If you provide notice numbers you must provide an organization')
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
            :value => [{ :policy_identifier => "2.16.840.1.12345.1.2.3.4.1",
              :cps_uris => ["http://example.com/cps","http://other.com/cps"],
              :user_notices => [ {:explicit_text => "thing", :organization => "my org", :notice_numbers => [1,2,3,4] }  ] }]
          }
          @cp = R509::Cert::Extensions::CertificatePolicies.new(@args)
        end

        it "creates extension" do
          @cp.should_not be_nil
          @cp.policies.count.should == 1
          @cp.policies[0].policy_identifier.should == "2.16.840.1.12345.1.2.3.4.1"
          @cp.policies[0].policy_qualifiers.cps_uris.should == ["http://example.com/cps", "http://other.com/cps"]
          @cp.policies[0].policy_qualifiers.user_notices.count.should == 1
          un = @cp.policies[0].policy_qualifiers.user_notices[0]
          un.notice_reference.notice_numbers.should == [1,2,3,4]
          un.notice_reference.organization.should == 'my org'
          un.explicit_text.should == "thing"
        end

        it "builds yaml" do
          YAML.load(@cp.to_yaml).should == @args
        end
      end

      context "multiple policies" do
        before :all do
          @args = {
            :critical => false,
            :value => [ {
              :policy_identifier => "2.16.840.1.99999.21.234",
              :cps_uris => ["http://example.com/cps","http://other.com/cps"],
              :user_notices => [ {:explicit_text => "this is a great thing", :organization => "my org", :notice_numbers => [1,2,3,4]} ]
            }, {
              :policy_identifier => "2.16.840.1.99999.21.235",
              :cps_uris => ["http://example.com/cps2"],
              :user_notices => [{:explicit_text => "this is a bad thing", :organization => "another org", :notice_numbers => [3,2,1] }, {:explicit_text => "another user notice"}]
            },
            {
              :policy_identifier => "2.16.840.1.99999.0"
            }]
          }
          @cp = R509::Cert::Extensions::CertificatePolicies.new(@args)
        end

        it "creates extension" do
          @cp.should_not be_nil
          @cp.policies.count.should == 3
          p0 = @cp.policies[0]
          p0.policy_identifier.should == "2.16.840.1.99999.21.234"
          p0.policy_qualifiers.cps_uris.should == ["http://example.com/cps", "http://other.com/cps"]
          p0.policy_qualifiers.user_notices.count.should == 1
          un0 = p0.policy_qualifiers.user_notices[0]
          un0.notice_reference.notice_numbers.should == [1,2,3,4]
          un0.notice_reference.organization.should == "my org"
          un0.explicit_text.should == "this is a great thing"
          p1 = @cp.policies[1]
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
          p2 = @cp.policies[2]
          p2.policy_identifier.should == "2.16.840.1.99999.0"
          p2.policy_qualifiers.should be_nil
        end

        it "builds yaml" do
          YAML.load(@cp.to_yaml).should == @args
        end
      end

      context "default criticality" do
        before :all do
          @args = { :value => [{ :policy_identifier => "2.16.840.1.12345.1.2.3.4.1" }] }
          @cp = R509::Cert::Extensions::CertificatePolicies.new(@args)
        end

        it "creates extension" do
          @cp.critical?.should be_false
        end

        it "builds yaml" do
          YAML.load(@cp.to_yaml).should == @args.merge(:critical => false)
        end
      end

      context "non-default criticality" do
        before :all do
          @args = { :value => [{ :policy_identifier => "2.16.840.1.12345.1.2.3.4.1" }], :critical => true }
          @cp = R509::Cert::Extensions::CertificatePolicies.new(@args)
        end

        it "creates extension" do
          @cp.critical?.should be_true
        end

        it "builds yaml" do
          YAML.load(@cp.to_yaml).should == @args
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
    pi.policy_identifier.should == '2.16.840.1.12345.1.2.3.4.1'
    pi.policy_qualifiers.should be_nil
  end

  it "loads data with a policy oid and a single qualifier" do
    data = OpenSSL::ASN1.decode "0U\u0006\v`\x86H\u0001\xE09\u0001\u0002\u0003\u0004\u00010F0\"\u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u0001\u0016\u0016http://example.com/cps0 \u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u0001\u0016\u0014http://other.com/cps"
    pi = R509::Cert::Extensions::CertificatePolicies::PolicyInformation.new(data)
    pi.policy_identifier.should == '2.16.840.1.12345.1.2.3.4.1'
    pi.policy_qualifiers.cps_uris.empty?.should == false
    pi.policy_qualifiers.user_notices.empty?.should == true
  end

  it "loads data with a policy oid and multiple qualifiers" do
    data = OpenSSL::ASN1.decode "0\x81\x94\u0006\n`\x86H\u0001\x86\x8D\u001F\u0015\x81k0\x81\x850#\u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u0001\u0016\u0017http://example.com/cps20;\u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u00020/0\u0018\u0016\vanother org0\t\u0002\u0001\u0003\u0002\u0001\u0002\u0002\u0001\u0001\u001A\u0013this is a bad thing0!\u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u00020\u0015\u001A\u0013another user notice"
    pi = R509::Cert::Extensions::CertificatePolicies::PolicyInformation.new(data)
    pi.policy_identifier.should == '2.16.840.1.99999.21.235'
    pi.policy_qualifiers.cps_uris.empty?.should == false
    pi.policy_qualifiers.user_notices.empty?.should == false
  end

  it "builds yaml" do
    data = OpenSSL::ASN1.decode "0\x81\x94\u0006\n`\x86H\u0001\x86\x8D\u001F\u0015\x81k0\x81\x850#\u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u0001\u0016\u0017http://example.com/cps20;\u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u00020/0\u0018\u0016\vanother org0\t\u0002\u0001\u0003\u0002\u0001\u0002\u0002\u0001\u0001\u001A\u0013this is a bad thing0!\u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u00020\u0015\u001A\u0013another user notice"
    pi = R509::Cert::Extensions::CertificatePolicies::PolicyInformation.new(data)
    YAML.load(pi.to_yaml).should == {:policy_identifier=>"2.16.840.1.99999.21.235", :cps_uris=>["http://example.com/cps2"], :user_notices=>[{:explicit_text=>"this is a bad thing", :organization=>"another org", :notice_numbers=>[3, 2, 1]}, {:explicit_text=>"another user notice"}]}
  end
end

describe R509::Cert::Extensions::CertificatePolicies::PolicyQualifiers do
  before :each do
    @pq = R509::Cert::Extensions::CertificatePolicies::PolicyQualifiers.new
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

  it "builds yaml" do
    data = OpenSSL::ASN1.decode "0#\u0006\b+\u0006\u0001\u0005\u0005\a\u0002\u0001\u0016\u0017http://example.com/cps2"
    @pq.parse(data)
    YAML.load(@pq.to_yaml).should == {:cps_uris=>["http://example.com/cps2"]}
  end
end

describe R509::Cert::Extensions::CertificatePolicies::UserNotice do
  it "loads data with both a notice reference and explicit text" do
    data = OpenSSL::ASN1.decode "0\u001F0\u0016\u0016\u0006my org0\f\u0002\u0001\u0001\u0002\u0001\u0002\u0002\u0001\u0003\u0002\u0001\u0004\u001A\u0005thing"
    un = R509::Cert::Extensions::CertificatePolicies::UserNotice.new(data)
    un.notice_reference.should_not be_nil
    un.explicit_text.should == 'thing'
  end

  it "loads data with a notice reference" do
    data = OpenSSL::ASN1.decode "0\u00180\u0016\u0016\u0006my org0\f\u0002\u0001\u0001\u0002\u0001\u0002\u0002\u0001\u0003\u0002\u0001\u0004"
    un = R509::Cert::Extensions::CertificatePolicies::UserNotice.new(data)
    un.notice_reference.should_not be_nil
    un.explicit_text.should be_nil
  end

  it "loads data with an explicit text" do
    data = OpenSSL::ASN1.decode "0\a\u001A\u0005thing"
    un = R509::Cert::Extensions::CertificatePolicies::UserNotice.new(data)
    un.notice_reference.should be_nil
    un.explicit_text.should == 'thing'
  end

  it "builds yaml" do
    data = OpenSSL::ASN1.decode "0\a\u001A\u0005thing"
    un = R509::Cert::Extensions::CertificatePolicies::UserNotice.new(data)
    YAML.load(un.to_yaml).should == {:explicit_text => "thing"}
  end
end

describe R509::Cert::Extensions::CertificatePolicies::NoticeReference do
  it "loads data with an org and no notice numbers" do
    data = OpenSSL::ASN1.decode "0\n\u0016\u0006my org0\u0000"
    nr = R509::Cert::Extensions::CertificatePolicies::NoticeReference.new(data)
    nr.organization.should == 'my org'
    nr.notice_numbers.should == []
  end

  it "loads data with an org and 1 notice number" do
    data = OpenSSL::ASN1.decode "0\r\u0016\u0006my org0\u0003\u0002\u0001\u0001"
    nr = R509::Cert::Extensions::CertificatePolicies::NoticeReference.new(data)
    nr.organization.should == 'my org'
    nr.notice_numbers.should == [1]
  end

  it "loads data with an org and more than 1 notice number" do
    data = OpenSSL::ASN1.decode "0\u0016\u0016\u0006my org0\f\u0002\u0001\u0001\u0002\u0001\u0002\u0002\u0001\u0003\u0002\u0001\u0004"
    nr = R509::Cert::Extensions::CertificatePolicies::NoticeReference.new(data)
    nr.organization.should == 'my org'
    nr.notice_numbers.should == [1,2,3,4]
  end

  it "builds yaml" do
    data = OpenSSL::ASN1.decode "0\u0016\u0016\u0006my org0\f\u0002\u0001\u0001\u0002\u0001\u0002\u0002\u0001\u0003\u0002\u0001\u0004"
    nr = R509::Cert::Extensions::CertificatePolicies::NoticeReference.new(data)
    YAML.load(nr.to_yaml).should == {:organization=>"my org", :notice_numbers=>[1, 2, 3, 4]}
  end
end
