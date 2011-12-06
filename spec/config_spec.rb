require 'spec_helper'
require 'r509/Config'
require 'r509/Exceptions'

describe R509::Config do
    context "when initialized with a cert and key" do
        before :each do
          @config = R509::Config.new(TestFixtures.test_ca_cert,
                                     TestFixtures.test_ca_key)
        end

        subject {@config}

        its(:message_digest) {should == "SHA1"}
        its(:crl_validity_hours) {should == 168}
        its(:cdp_location) {should be_nil}
        its(:ocsp_location) {should be_nil}
        its(:crl_number) {should == 0}
        its(:revoked_certs) {should == []}

        it "should have the proper CA cert" do
            @config.ca_cert.to_pem.should == TestFixtures.test_ca_cert.to_pem
        end

        it "should have the proper CA key" do
            @config.ca_key.to_pem.should == TestFixtures.test_ca_key.to_pem
        end
    end

end
