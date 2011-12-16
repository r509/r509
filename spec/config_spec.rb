require 'spec_helper'
require 'r509/Config'
require 'r509/Exceptions'

describe R509::Config do
    context "when initialized with a cert and key" do
        before :each do
            @config = R509::Config.new(
                :ca_cert => TestFixtures.test_ca_cert
            )
        end

        subject {@config}

        its(:message_digest) {should == "SHA1"}
        its(:crl_validity_hours) {should == 168}
        its(:cdp_location) {should be_nil}
        its(:ocsp_location) {should be_nil}
        its(:num_profiles) {should == 0}

        it "should have the proper CA cert" do
            @config.ca_cert.to_pem.should == TestFixtures.test_ca_cert.to_pem
        end

        it "should have the proper CA key" do
            @config.ca_cert.key.to_pem.should == TestFixtures.test_ca_cert.key.to_pem
        end

        it "raises an error if you don't pass :ca_cert" do
            expect { R509::Config.new(:crl_validity_hours => 2) }.to raise_error ArgumentError, 'Config object requires that you pass :ca_cert'
        end
        it "raises an error if :ca_cert is not of type R509::Cert" do
            expect { R509::Config.new(:ca_cert => 'not a cert, and not right type') }.to raise_error ArgumentError, ':ca_cert must be of type R509::Cert'
        end
        it "raises an error if :ca_cert does not contain a private key" do
            expect { R509::Config.new( :ca_cert => R509::Cert.new( :cert => TestFixtures::TEST_CA_CERT) ) }.to raise_error ArgumentError, ':ca_cert object must contain a private key, not just a certificate'
        end
        it "raises an error if :ocsp_cert that is not R509::Cert" do
            expect { R509::Config.new(:ca_cert => TestFixtures.test_ca_cert, :ocsp_cert => "not a cert") }.to raise_error ArgumentError, ':ocsp_cert, if provided, must be of type R509::Cert'
        end
        it "raises an error if :ocsp_cert does not contain a private key" do
            expect { R509::Config.new( :ca_cert => TestFixtures.test_ca_cert, :ocsp_cert => R509::Cert.new( :cert => TestFixtures::TEST_CA_CERT) ) }.to raise_error ArgumentError, ':ocsp_cert must contain a private key, not just a certificate'
        end
        it "returns the correct cert object on #ocsp_cert if none is specified" do
            @config.ocsp_cert.should == @config.ca_cert
        end
        it "returns the correct cert object on #ocsp_cert if an ocsp_cert was specified" do
            ocsp_cert = R509::Cert.new(
                :cert => TestFixtures::TEST_CA_OCSP_CERT,
                :key => TestFixtures::TEST_CA_OCSP_KEY
            )
            config = R509::Config.new(
                :ca_cert => TestFixtures.test_ca_cert,
                :ocsp_cert => ocsp_cert
            )

            config.ocsp_cert.should == ocsp_cert
        end
        it "fails to specify a non-ConfigProfile as the profile" do
            config = R509::Config.new(
                :ca_cert => TestFixtures.test_ca_cert
            )

            expect{ config.set_profile("bogus", "not a ConfigProfile")}.to raise_error TypeError
        end

        it "shouldn't let you specify a profile that's not a ConfigProfile, on instantiation" do
            expect{ R509::Config.new(
                :ca_cert => TestFixtures.test_ca_cert,
                :profiles => { "first_profile" => "not a ConfigProfile" }
            ) }.to raise_error TypeError
        end

        it "can specify a single profile" do
            first_profile = R509::ConfigProfile.new

            config = R509::Config.new(
                :ca_cert => TestFixtures.test_ca_cert,
                :profiles => { "first_profile" => first_profile }
            )

            config.profile("first_profile").should == first_profile
        end

        it "should load YAML" do
            config = R509::Config.from_yaml("test_ca", File.read("#{File.dirname(__FILE__)}/fixtures/config_test.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"})
            config.crl_validity_hours.should == 168
            config.message_digest.should == "SHA1"
            config.num_profiles.should == 2
        end

        it "should load YAML which only has a CA Cert and Key defined" do
            config = R509::Config.from_yaml("test_ca", File.read("#{File.dirname(__FILE__)}/fixtures/config_test_minimal.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"})
            config.num_profiles.should == 0
        end

        it "should fail if YAML config is null" do
            expect{ R509::Config.from_yaml("no_config_here", File.read("#{File.dirname(__FILE__)}/fixtures/config_test.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"}) }.to raise_error(ArgumentError)
        end

        it "should fail if YAML config isn't a hash" do
            expect{ R509::Config.from_yaml("config_is_string", File.read("#{File.dirname(__FILE__)}/fixtures/config_test.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"}) }.to raise_error(ArgumentError)
        end

        it "should fail if YAML config doesn't give a root CA directory that's a directory" do
            expect{ R509::Config.from_yaml("test_ca", File.read("#{File.dirname(__FILE__)}/fixtures/config_test.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures/no_directory_here"}) }.to raise_error(R509::R509Error)
        end

        it "should load YAML from filename" do
            config = R509::Config.load_yaml("test_ca", "#{File.dirname(__FILE__)}/fixtures/config_test.yaml", {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"})
            config.crl_validity_hours.should == 168
            config.message_digest.should == "SHA1"
        end

        it "can specify crl_number_file" do
            config = R509::Config.new(
                :ca_cert => TestFixtures.test_ca_cert,
                :crl_number_file => "crl_number_file.txt"
            )
            config.crl_number_file.should == 'crl_number_file.txt'
        end

        it "can specify crl_list_file" do
            config = R509::Config.new(
                :ca_cert => TestFixtures.test_ca_cert,
                :crl_list_file => "crl_list_file.txt"
            )
            config.crl_list_file.should == 'crl_list_file.txt'
        end
    end

end
