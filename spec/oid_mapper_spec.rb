require 'spec_helper'
require 'r509/oid_mapper'

# NOTE
# The nature of OID registration means that the state does NOT get reset between
# each test. Accordingly, we MUST use OIDs (and short names) here that will not
# be present in any other tests (or in the real world)

describe R509::OIDMapper do
  it "registers one new oid" do
    subject = R509::Subject.new [['1.4.3.2.1.2.3.5.5.5.5.5', 'random_oid']]
    expect(subject['1.4.3.2.1.2.3.5.5.5.5.5']).to eq('random_oid')
    expect { R509::Subject.new [['myOIDName', 'random_oid']] }.to raise_error(OpenSSL::X509::NameError, 'invalid field name')

    expect(R509::OIDMapper.register('1.4.3.2.1.2.3.5.5.5.5.5', 'myOIDName')).to eq(true)
    subject_new = R509::Subject.new [['myOIDName', 'random_oid']]
    expect(subject_new['myOIDName']).to eq('random_oid')
  end

  it "returns false when registering an oid that already exists" do
    expect(R509::OIDMapper.register('1.4.3.2.1.2.7.4.4.4.4', 'someOtherName')).to eq(true)
    expect(R509::OIDMapper.register('1.4.3.2.1.2.7.4.4.4.4', 'someOtherName')).to eq(false)
  end

  it "registers a batch of new oids" do
    expect { R509::Subject.new [['testOIDName', 'random_oid']] }.to raise_error(OpenSSL::X509::NameError, 'invalid field name')
    expect { R509::Subject.new [['anotherOIDName', 'second_random']] }.to raise_error(OpenSSL::X509::NameError, 'invalid field name')
    R509::OIDMapper.batch_register([
      { :oid => '1.4.3.2.1.2.3.4.4.4.4', :short_name => 'testOIDName' },
      { :oid => '1.4.3.2.1.2.5.4.4.4.4', :short_name => 'anotherOIDName' }
    ])
    subject_new = R509::Subject.new [['testOIDName', 'random_oid'], ['anotherOIDName', 'second_random']]
    expect(subject_new['testOIDName']).to eq('random_oid')
    expect(subject_new['anotherOIDName']).to eq('second_random')
  end

  it "registers a batch of oids from YAML" do
    expect { R509::Subject.new [['thirdOIDName', 'random_oid']] }.to raise_error(OpenSSL::X509::NameError, 'invalid field name')
    expect { R509::Subject.new [['fourthOIDName', 'second_random']] }.to raise_error(OpenSSL::X509::NameError, 'invalid field name')
    yaml_data = "---\ncustom_oids:\n- :oid: 1.4.3.2.1.2.3.4.4.4.5\n  :short_name: thirdOIDName\n- :oid: 1.4.3.2.1.2.5.4.4.4.5\n  :short_name: fourthOIDName\n"
    R509::OIDMapper.register_from_yaml("custom_oids", yaml_data)
    subject_new = R509::Subject.new [['thirdOIDName', 'random_oid'], ['fourthOIDName', 'second_random']]
    expect(subject_new['thirdOIDName']).to eq('random_oid')
    expect(subject_new['fourthOIDName']).to eq('second_random')
  end
end
