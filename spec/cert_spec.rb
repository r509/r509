require 'spec_helper'

describe R509::Cert do
    before :all do
        @cert = TestFixtures::CERT
        @cert_public_key_modulus = TestFixtures::CERT_PUBLIC_KEY_MODULUS
        @cert3 = TestFixtures::CERT3
        @cert_der = TestFixtures::CERT_DER
        @cert_san = TestFixtures::CERT_SAN
        @cert_san2 = TestFixtures::CERT_SAN2
        @key3 = TestFixtures::KEY3
        @cert3_p12 = TestFixtures::CERT3_P12
        @cert4 = TestFixtures::CERT4
        @key3_encrypted = TestFixtures::KEY3_ENCRYPTED
        @cert5 = TestFixtures::CERT5
        @cert6 = TestFixtures::CERT6
        @test_ca_cert = TestFixtures::TEST_CA_CERT
        @cert_expired = TestFixtures::CERT_EXPIRED
        @cert_not_yet_valid = TestFixtures::CERT_NOT_YET_VALID
    end
    it "raises error when no hash supplied" do
        expect { R509::Cert.new('no hash')}.to raise_error(ArgumentError, 'Must provide a hash of options')
    end
    it "raises error when no :cert supplied" do
        expect { R509::Cert.new(:key => "random")}.to raise_error(ArgumentError, 'Must provide :cert or :pkcs12')
    end
    it "raises error when :cert and :pkcs12 are both provided" do
        expect { R509::Cert.new(
            :key => @key3,
            :pkcs12 => @cert3_p12,
            :password => 'whatever'
        ) }.to raise_error(ArgumentError, 'When providing pkcs12, do not pass cert or key')
    end
    it "raises error when :key and :pkcs12 are both provided" do
        expect { R509::Cert.new(
            :cert => @cert,
            :pkcs12 => @cert3_p12,
            :password => 'whatever'
        ) }.to raise_error(ArgumentError, 'When providing pkcs12, do not pass cert or key')
    end
    it "has a public_key" do
        cert = R509::Cert.new(:cert => @cert)
        #this is more complex than it should have to be. diff versions of openssl
        #return subtly diff PEM encodings so we need to look at the modulus (n)
        #but beware, because n is not present for DSA certificates
        cert.public_key.n.to_i.should == @cert_public_key_modulus.to_i
    end
    it "returns bit strength" do
        cert = R509::Cert.new(:cert => @cert)
        cert.bit_strength.should == 2048
    end
    it "has the right issuer" do
        cert = R509::Cert.new(:cert => @cert)
        cert.issuer.to_s.should == "/C=US/O=SecureTrust Corporation/CN=SecureTrust CA"
    end
    it "generates certificate fingerprints" do
        cert = R509::Cert.new(:cert => @cert)
        cert.fingerprint.should == '863bbb58877b426eb10ccfd34d3056b8c961f627'
        cert.fingerprint('sha256').should == '65d624f5a6937c3005d78b3f4ff09164649dd5aeb3fd8a93d6fd420e8b587fa2'
        cert.fingerprint('sha512').should == 'a07d87f04161f52ef671c9d616530d07ebadef9c93c0470091617363c9ce8618dcb7931414e599d25cb032d68597111719e76d7de4bb7a92bf5ca7c08c36cf12'
        cert.fingerprint('md5').should == 'aa78501c41b19252dfbe8ba509cc21f4'
    end
    it "returns true from has_private_key? when a key is present" do
        cert = R509::Cert.new(:cert => @cert3, :key => @key3)
        cert.has_private_key?.should == true
    end
    it "returns false from has_private_key? when a key is not present" do
        cert = R509::Cert.new(:cert => @cert)
        cert.has_private_key?.should == false
    end
    it "loads encrypted private key with cert" do
        expect { R509::Cert.new(:cert => @cert3, :key => @key3_encrypted, :password => "r509") }.to_not raise_error
    end
    it "loads pkcs12" do
        cert = R509::Cert.new(:pkcs12 => @cert3_p12, :password => "r509")
        cert.has_private_key?.should == true
        cert.subject.to_s.should == '/CN=futurama.com/O=Farnsworth Enterprises'
    end
    it "has the right not_before" do
        cert = R509::Cert.new(:cert => @cert)
        cert.not_before.to_i.should == 1282659002
    end
    it "has the right not_after" do
        cert = R509::Cert.new(:cert => @cert)
        cert.not_after.to_i.should == 1377267002
    end
    it "fetches a subject component" do
        cert = R509::Cert.new(:cert => @cert)
        cert.subject_component('CN').should == 'langui.sh'
    end
    it "fetches a subject component for mixed-case components" do
        cert4 = R509::Cert.new(:cert => @cert4)
        cert4.subject_component('emailAddress').should == 'support@polycom.com'

        cert6 = R509::Cert.new(:cert => @cert6)
        cert6.subject_component('serialNumber').should == 'a/3ILmX9qynk8f3WafoTTkKgWj0LAGRL'
    end
    it "returns nil when subject component not found" do
        cert = R509::Cert.new(:cert => @cert)
        cert.subject_component('OU').should be_nil
    end
    it "returns signature algorithm" do
        cert = R509::Cert.new(:cert => @cert)
        cert.signature_algorithm.should == 'sha1WithRSAEncryption'
    end
    it "returns the RSA key algorithm" do
        cert = R509::Cert.new(:cert => @cert)
        cert.key_algorithm.should == 'RSA'
    end
    it "returns the DSA key algorithm" do
        cert = R509::Cert.new(:cert => @cert6)
        cert.key_algorithm.should == 'DSA'
    end
    it "returns list of san_names when it is a san cert" do
        cert = R509::Cert.new(:cert => @cert_san)
        cert.san_names.should == ['langui.sh']
    end
    it "returns an empty list when it is not a san cert" do
        cert = R509::Cert.new(:cert => @cert)
        cert.san_names.should == []
    end
    it "#subject_names should return a list of san_names in addition to the CN" do
        cert = R509::Cert.new(:cert => @cert_san2)
        cert.subject_names.should == ["cn.langui.sh", "san1.langui.sh",
                                      "san2.langui.sh", "san3.langui.sh"]
    end
    it "#subject_names should not have duplicates" do
        cert = R509::Cert.new(:cert => @cert_san)
        cert.subject_names.should == ["langui.sh"]
    end
    it "#subject_names should return the CN in the array, if there are no SANs" do
        cert = R509::Cert.new(:cert => @cert)
        cert.subject_names.should == ["langui.sh"]
    end
    it "raises exception when providing invalid cert" do
        expect { R509::Cert.new(:cert => "invalid cert") }.to raise_error(OpenSSL::X509::CertificateError)
    end
    it "raises exception when providing invalid key" do
        expect { R509::Cert.new(:cert => @cert, :key => 'invalid key') }.to raise_error(R509::R509Error, 'Failed to load private key. Invalid key or incorrect password.')
    end
    it "raises exception on non-matching key" do
        expect { R509::Cert.new(:cert => @cert, :key => @key3) }.to raise_error(R509::R509Error, 'Key does not match cert.')
    end
    it "return normal object on matching key/cert pair" do
        expect { R509::Cert.new(:cert => @cert3, :key => @key3) }.to_not raise_error
    end
    it "loads properly when an R509::PrivateKey is provided" do
        key = R509::PrivateKey.new(:key => @key3)
        expect { R509::Cert.new(:key => key, :cert => @cert3)}.to_not raise_error
    end
    it "writes to pem" do
        cert = R509::Cert.new(:cert => @cert)
        sio = StringIO.new
        sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
        cert.write_pem(sio)
        sio.string.should == @cert + "\n"
    end
    it "writes to der" do
        cert = R509::Cert.new(:cert => @cert)
        sio = StringIO.new
        sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
        cert.write_der(sio)
        sio.string.should == @cert_der
    end
    it "writes to pkcs12 when key/cert are present" do
        cert = R509::Cert.new(:cert => @cert3, :key => @key3)
        sio = StringIO.new
        sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
        cert.write_pkcs12(sio,'r509_password')
        expect { R509::Cert.new(:pkcs12 => sio.string, :password => 'r509_password') }.to_not raise_error
    end
    it "raises error when writing to pkcs12 if key is not present" do
        cert = R509::Cert.new(:cert => @cert3)
        expect { cert.write_pkcs12('/dev/null','password') }.to raise_error(R509::R509Error, "Writing a PKCS12 requires both key and cert")
    end
    it "parses san extension" do
        cert = R509::Cert.new(:cert => @cert_san)
        cert.san_names.should == ["langui.sh"]
    end
    context "when initialized with an OpenSSL::X509::Certificate" do
        it "returns pem on to_pem" do
            test_cert = OpenSSL::X509::Certificate.new(@cert)
            cert = R509::Cert.new(:cert => test_cert)
            cert.to_pem.should == @cert
        end
        it "returns der on to_der" do
            test_cert = OpenSSL::X509::Certificate.new(@cert)
            cert = R509::Cert.new(:cert => test_cert)
            cert.to_der.should == @cert_der
        end
        it "returns pem on to_s" do
            test_cert = OpenSSL::X509::Certificate.new(@cert)
            cert = R509::Cert.new(:cert => test_cert)
            cert.to_s.should == @cert
        end
    end
    context "when initialized with a pem" do
        it "returns on to_pem" do
            cert = R509::Cert.new(:cert => @cert)
            cert.to_pem.should == @cert
        end
        it "returns der on to_der" do
            cert = R509::Cert.new(:cert => @cert)
            cert.to_der.should == @cert_der
        end
        it "returns pem on to_s" do
            cert = R509::Cert.new(:cert => @cert)
            cert.to_s.should == @cert
       end
    end
    it "gets key usage from the extensions array" do
        cert = R509::Cert.new(:cert => @cert)
        cert.extensions["keyUsage"].nil?.should == false
        cert.extensions["keyUsage"]["value"].should == "Digital Signature, Key Encipherment"
    end
    it "gets extended key usage from the extensions array" do
        cert = R509::Cert.new(:cert => @cert)
        cert.extensions["extendedKeyUsage"].nil?.should == false
        cert.extensions["extendedKeyUsage"]["value"].should == "TLS Web Server Authentication"
    end
    
    it "gets the right object from #basic_constraints" do
        cert = R509::Cert.new(:cert => @cert)
        cert.basic_constraints.class.should == R509::Cert::Extensions::BasicConstraints
    end
    it "gets the right object from #key_usage" do
        cert = R509::Cert.new(:cert => @cert)
        cert.key_usage.class.should == R509::Cert::Extensions::KeyUsage
    end
    it "gets the right object from #key_usage" do
        cert = R509::Cert.new(:cert => @cert)
        cert.extended_key_usage.class.should == R509::Cert::Extensions::ExtendedKeyUsage
    end
    it "gets the right object from #subject_key_identifier" do
        cert = R509::Cert.new(:cert => @cert)
        cert.subject_key_identifier.class.should == R509::Cert::Extensions::SubjectKeyIdentifier
    end
    it "gets the right object from #authority_key_identifier" do
        cert = R509::Cert.new(:cert => @cert)
        cert.authority_key_identifier.class.should == R509::Cert::Extensions::AuthorityKeyIdentifier
    end
    it "gets the right object from #subject_alternative_name" do
        cert = R509::Cert.new(:cert => @cert5)
        cert.subject_alternative_name.class.should == R509::Cert::Extensions::SubjectAlternativeName
    end
    it "gets the right object from #authority_info_access" do
        cert = R509::Cert.new(:cert => @cert5)
        cert.authority_info_access.class.should == R509::Cert::Extensions::AuthorityInfoAccess
    end
    it "gets the right object from #crl_distribution_points" do
        cert = R509::Cert.new(:cert => @cert)
        cert.crl_distribution_points.class.should == R509::Cert::Extensions::CrlDistributionPoints
    end

    it "checks rsa?" do
        cert = R509::Cert.new(:cert => @cert)
        cert.rsa?.should == true
        cert.dsa?.should == false
    end
    it "gets RSA bit strength" do
        cert = R509::Cert.new(:cert => @cert)
        cert.bit_strength.should == 2048
    end
    it "checks dsa?" do
        cert = R509::Cert.new(:cert => @cert6)
        cert.rsa?.should == false
        cert.dsa?.should == true
    end
    it "gets DSA bit strength" do
        cert = R509::Cert.new(:cert => @cert6)
        cert.bit_strength.should == 1024
    end
    it "gets serial of cert" do
        cert = R509::Cert.new(:cert => @cert6)
        cert.serial.should == 951504
    end
    it "checks a cert that is not yet valid" do
        cert = R509::Cert.new(:cert => @cert_not_yet_valid)
        cert.valid?.should == false
    end
    it "checks a cert that is in validity range" do
        cert = R509::Cert.new(:cert => @test_ca_cert)
        cert.valid?.should == true
    end
    it "checks a cert that is expired" do
        cert = R509::Cert.new(:cert => @cert_expired)
        cert.valid?.should == false
    end
    it "checks expired_at?" do
        cert = R509::Cert.new(:cert => @cert_expired)
        cert.valid_at?(Time.utc(2009,1,1)).should == false
        cert.valid_at?(Time.utc(2011,3,1)).should == true
        cert.valid_at?(1298959200).should == true
        cert.valid_at?(Time.utc(2012,1,1)).should == false
    end
end
