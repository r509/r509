require 'spec_helper'
require 'r509/OidMapper'


# NOTE
# The nature of OID registration means that the state does NOT get reset between
# each test. Accordingly, we MUST use OIDs (and short names) here that will not
# be present in any other tests (or in the real world)

describe R509::OidMapper do
    it "registers one new oid" do
        subject = R509::Subject.new [['1.4.3.2.1.2.3.5.5.5.5.5','random_oid']]
        subject['1.4.3.2.1.2.3.5.5.5.5.5'].should == 'random_oid'
        expect { R509::Subject.new [['myOidName','random_oid']] }.to raise_error(OpenSSL::X509::NameError,'invalid field name')

        R509::OidMapper.register('1.4.3.2.1.2.3.5.5.5.5.5','myOidName').should == true
        subject_new = R509::Subject.new [['myOidName','random_oid']]
        subject_new['myOidName'].should == 'random_oid'
    end
    it "registers a batch of new oids" do
        expect { R509::Subject.new [['testOidName','random_oid']] }.to raise_error(OpenSSL::X509::NameError,'invalid field name')
        expect { R509::Subject.new [['anotherOidName','second_random']] }.to raise_error(OpenSSL::X509::NameError,'invalid field name')
        R509::OidMapper.batch_register([
        {:oid => '1.4.3.2.1.2.3.4.4.4.4', :short_name => 'testOidName'},
        {:oid => '1.4.3.2.1.2.5.4.4.4.4', :short_name => 'anotherOidName'}
        ])
        subject_new = R509::Subject.new [['testOidName','random_oid'],['anotherOidName','second_random']]
        subject_new['testOidName'].should == 'random_oid'
        subject_new['anotherOidName'].should == 'second_random'
    end
end
