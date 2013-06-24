require 'spec_helper'
require 'r509/oid_mapper'


# NOTE
# The nature of OID registration means that the state does NOT get reset between
# each test. Accordingly, we MUST use OIDs (and short names) here that will not
# be present in any other tests (or in the real world)

describe R509::OIDMapper do
  it "registers one new oid" do
    subject = R509::Subject.new [['1.4.3.2.1.2.3.5.5.5.5.5','random_oid']]
    subject['1.4.3.2.1.2.3.5.5.5.5.5'].should == 'random_oid'
    expect { R509::Subject.new [['myOIDName','random_oid']] }.to raise_error(OpenSSL::X509::NameError,'invalid field name')

    R509::OIDMapper.register('1.4.3.2.1.2.3.5.5.5.5.5','myOIDName').should == true
    subject_new = R509::Subject.new [['myOIDName','random_oid']]
    subject_new['myOIDName'].should == 'random_oid'
  end

  it "registers a batch of new oids" do
    expect { R509::Subject.new [['testOIDName','random_oid']] }.to raise_error(OpenSSL::X509::NameError,'invalid field name')
    expect { R509::Subject.new [['anotherOIDName','second_random']] }.to raise_error(OpenSSL::X509::NameError,'invalid field name')
    R509::OIDMapper.batch_register([
    {:oid => '1.4.3.2.1.2.3.4.4.4.4', :short_name => 'testOIDName'},
    {:oid => '1.4.3.2.1.2.5.4.4.4.4', :short_name => 'anotherOIDName'}
    ])
    subject_new = R509::Subject.new [['testOIDName','random_oid'],['anotherOIDName','second_random']]
    subject_new['testOIDName'].should == 'random_oid'
    subject_new['anotherOIDName'].should == 'second_random'
  end

  it "registers a batch of oids from YAML" do
    expect { R509::Subject.new [['thirdOIDName','random_oid']] }.to raise_error(OpenSSL::X509::NameError,'invalid field name')
    expect { R509::Subject.new [['fourthOIDName','second_random']] }.to raise_error(OpenSSL::X509::NameError,'invalid field name')
    yaml_data = "---\ncustom_oids:\n- :oid: 1.4.3.2.1.2.3.4.4.4.5\n  :short_name: thirdOIDName\n- :oid: 1.4.3.2.1.2.5.4.4.4.5\n  :short_name: fourthOIDName\n"
    R509::OIDMapper.register_from_yaml("custom_oids", yaml_data)
    subject_new = R509::Subject.new [['thirdOIDName','random_oid'],['fourthOIDName','second_random']]
    subject_new['thirdOIDName'].should == 'random_oid'
    subject_new['fourthOIDName'].should == 'second_random'
  end
end
