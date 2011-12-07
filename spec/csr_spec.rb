require 'spec_helper'
require 'stringio'


describe R509::Csr do
    before :all do
        @cert = TestFixtures::CERT
        @cert_san = TestFixtures::CERT_SAN
        @csr = TestFixtures::CSR
        @csr_public_key_modulus = TestFixtures::CSR_PUBLIC_KEY_MODULUS
        @csr_invalid_signature = TestFixtures::CSR_INVALID_SIGNATURE
        @csr2 = TestFixtures::CSR2
        @csr3 = TestFixtures::CSR3
        @csr_der = TestFixtures::CSR_DER
        @csr_dsa = TestFixtures::CSR_DSA
        @csr4_multiple_attrs = TestFixtures::CSR4_MULTIPLE_ATTRS
        @key3 = TestFixtures::KEY3
        @key_csr2 = TestFixtures::KEY_CSR2
    end

    it "writes to pem" do
        csr = R509::Csr.new(@csr)
    sio = StringIO.new
    sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
        csr.write_pem(sio)
    sio.string.should == @csr
    end
    it "writes to der" do
    sio = StringIO.new
    sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
        csr = R509::Csr.new(@csr)
        csr.write_der(sio)
        sio.string.should == @csr_der
    end
    context "when initialized" do
        it "returns nil on to_pem" do
            csr = R509::Csr.new
            csr.to_pem.should == nil
        end
        it "returns nil on to_der" do
            csr = R509::Csr.new
            csr.to_der.should == nil
        end
        it "returns nil on to_s" do
            csr = R509::Csr.new
            csr.to_s.should == nil
        end
        it "returns nil on key_algorithm" do
            csr = R509::Csr.new
            csr.key_algorithm.should == nil
        end
        it "Uses SHA1 as the default signature algorithm" do
            csr = R509::Csr.new
            csr.message_digest.should == 'sha1'
        end
        it "raises exception when providing invalid csr" do
            expect { R509::Csr.new('invalid csr') }.to raise_error(OpenSSL::X509::RequestError)
        end
        it "raises exception when providing invalid key" do
            expect { R509::Csr.new(@csr,'invalid key') }.to raise_error(OpenSSL::PKey::RSAError)
        end
        it "raises exception with too many params" do
            expect { R509::Csr.new(@csr3,@key3,'thirdparam') }.to raise_error(ArgumentError)
        end
        it "returns false from verify_signature with no CSR present" do
            csr = R509::Csr.new
            csr.verify_signature.should == false
        end
    end
    context "when passing a cert (single param) to create_with_cert" do
        it "returns a valid pem" do
            csr = R509::Csr.new
            csr.create_with_cert @cert,1024
            csr.to_pem.should match(/CERTIFICATE REQUEST/)
        end
        it "has a public key length of 2048 by default" do
            csr = R509::Csr.new
            csr.create_with_cert @cert
            csr.bit_strength.should == 2048
        end
        it "encodes the subject data from the cert" do
            csr = R509::Csr.new
            csr.create_with_cert @cert,1024
            csr.subject.to_s.should == '/C=US/ST=Illinois/L=Chicago/O=Paul Kehrer/CN=langui.sh'
        end
        it "san domains from the cert should be encoded in the request" do
            csr = R509::Csr.new
            csr.create_with_cert @cert_san,1024
            csr.san_names.should == ['langui.sh']
        end
    end
    context "when passing a 1024 key length to create_with_cert" do
        it "has a public key length of 1024" do
            csr = R509::Csr.new
            csr.create_with_cert @cert,1024
            csr.bit_strength.should == 1024
        end
    end
    context "when passing a list of domains to create_with_cert" do
        it "duplicates should be removed" do
            csr = R509::Csr.new
            csr.create_with_cert @cert, 1024, ['langui.sh','victoly.com','victoly.com','domain.local','victoly.com']
            csr.san_names.should == ["langui.sh", "victoly.com", "domain.local"]
        end
    end
    context "when passing an array to create_with_subject" do
        it "generates a matching csr" do
            csr = R509::Csr.new
            csr.create_with_subject [['CN','langui.sh'],['ST','Illinois'],['L','Chicago'],['C','US'],['emailAddress','ca@langui.sh']],1024
            csr.subject.to_s.should == '/CN=langui.sh/ST=Illinois/L=Chicago/C=US/emailAddress=ca@langui.sh'
        end
        it "generates a matching csr with san domains" do
            csr = R509::Csr.new
            csr.create_with_subject [['CN','langui.sh'],['emailAddress','ca@langui.sh']],1024,['domain2.com','domain3.com']
            csr.subject.to_s.should == '/CN=langui.sh/emailAddress=ca@langui.sh'
            csr.san_names.should == ["domain2.com", "domain3.com"]
        end
        it "generates a matching csr when supplying raw oids" do
            csr = R509::Csr.new
            csr.create_with_subject [['2.5.4.3','common name'],['2.5.4.15','business category'],['2.5.4.7','locality'],['1.3.6.1.4.1.311.60.2.1.3','jurisdiction oid openssl typically does not know']],1024
            # we want the subject to be able to be one of two things, depending on how old your computer is
            # the "Be" matcher will call .include? on the array here because of be_include
            # does anyone know of a better, less stupid way to do this?
            ['/CN=common name/businessCategory=business category/L=locality/1.3.6.1.4.1.311.60.2.1.3=jurisdiction oid openssl typically does not know',"/CN=common name/2.5.4.15=business category/L=locality/1.3.6.1.4.1.311.60.2.1.3=jurisdiction oid openssl typically does not know"].should be_include csr.subject.to_s
        end
    end
    context "when supplying an existing csr" do
        it "populates the bit_strength" do
            csr = R509::Csr.new @csr
            csr.bit_strength.should == 2048
        end
        it "populates the subject" do
            csr = R509::Csr.new @csr
            csr.subject.to_s.should == '/CN=test.local/O=Testing CSR'
        end
        it "parses the san names" do
            csr = R509::Csr.new @csr
            csr.san_names.should == ["test.local", "additionaldomains.com", "saniam.com"]
        end
        it "parses san names when there are multiple non-SAN attributes" do
            csr = R509::Csr.new @csr4_multiple_attrs
            csr.san_names.should == ["adomain.com", "anotherdomain.com", "justanexample.com"]
        end
        it "fetches a subject component" do
            csr = R509::Csr.new @csr
            csr.subject_component('CN').to_s.should == 'test.local'
        end
        it "returns the signature algorithm" do
            csr = R509::Csr.new @csr
            csr.signature_algorithm.should == 'sha1WithRSAEncryption'
        end
        it "returns RSA key algorithm for RSA CSR" do
            csr = R509::Csr.new @csr
            csr.key_algorithm.should == 'RSA'
        end
        it "returns DSA key algorithm for DSA CSR" do
            csr = R509::Csr.new @csr_dsa
            csr.key_algorithm.should == 'DSA'
        end
        it "returns the public key" do
            #this is more complex than it should have to be. diff versions of openssl
            #return subtly diff PEM encodings so we need to look at the modulus (n)
            #but beware, because n is not present for DSA certificates
            csr = R509::Csr.new @csr
            csr.public_key.n.to_i.should == @csr_public_key_modulus.to_i
        end
        it "returns true with valid signature" do
            csr = R509::Csr.new @csr
            csr.verify_signature.should == true
        end
        it "returns false on invalid signature" do
            csr = R509::Csr.new @csr_invalid_signature
            csr.verify_signature.should == false
        end
    end
    context "when supplying a key with csr" do
        it "raises exception on non-matching key" do
            expect { R509::Csr.new(@csr,@key_csr2) }.to raise_error(R509::R509Error)
        end
        it "accepts matching key" do
            csr = R509::Csr.new(@csr2,@key_csr2)
            csr.to_pem.should == @csr2
        end
    end
    context "when setting alternate signature algorithms" do
        it "sets sha1 properly after setting to another hash" do
            csr = R509::Csr.new
            csr.message_digest = 'sha256'
            csr.message_digest.should == 'sha256'
            csr.message_digest = 'sha1'
            csr.message_digest.should == 'sha1'
            csr.create_with_subject [['CN','sha1-signature-alg.test']],1024
            csr.signature_algorithm.should == "sha1WithRSAEncryption"
        end
        it "sets sha1 if you pass an invalid message digest" do
            csr = R509::Csr.new
            csr.message_digest = 'sha88'
            csr.message_digest.should == 'sha1'
        end
        it "sets sha256 properly" do
            csr = R509::Csr.new
            csr.message_digest = 'sha256'
            csr.message_digest.should == 'sha256'
            csr.create_with_subject [['CN','sha256-signature-alg.test']],1024
            csr.signature_algorithm.should == "sha256WithRSAEncryption"
        end
        it "sets sha512 properly" do
            csr = R509::Csr.new
            csr.message_digest = 'sha512'
            csr.message_digest.should == 'sha512'
            csr.create_with_subject [['CN','sha512-signature-alg.test']],1024
            csr.signature_algorithm.should == "sha512WithRSAEncryption"
        end
        it "sets md5 properly" do
            csr = R509::Csr.new
            csr.message_digest = 'md5'
            csr.message_digest.should == 'md5'
            csr.create_with_subject [['CN','md5-signature-alg.test']],1024
            csr.signature_algorithm.should == "md5WithRSAEncryption"
        end
    end
    it "checks rsa?" do
        csr = R509::Csr.new(@csr)
        csr.rsa?.should == true
        csr.dsa?.should == false
    end
    it "gets RSA bit strength" do
        csr = R509::Csr.new(@csr)
        csr.bit_strength.should == 2048
    end
    it "checks dsa?" do
        csr = R509::Csr.new(@csr_dsa)
        csr.rsa?.should == false
        csr.dsa?.should == true
    end
    it "gets DSA bit strength" do
        csr = R509::Csr.new(@csr_dsa)
        csr.bit_strength.should == 1024
    end

end
