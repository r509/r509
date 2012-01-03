require 'spec_helper'
require 'pathname'
require 'r509/io_helpers'

module TestFixtures
    extend R509::IOHelpers

    FIXTURES_PATH = Pathname.new(__FILE__).dirname + "fixtures"

    def self.read_fixture(filename)
        read_data((FIXTURES_PATH + filename).to_s)
    end

    #Trustwave cert for langui.sh
    CERT = read_fixture('cert1.pem')

    #Trustwave root cert
    STCA_CERT = read_fixture('stca.pem')

    CERT_PUBLIC_KEY_MODULUS = read_fixture('cert1_public_key_modulus.txt')

    # cert without key usage
    CERT4 = read_fixture('cert4.pem')

    # cert with multiple EKU
    CERT5 = read_fixture('cert5.pem')

    # cert with DSA public key
    CERT6 = read_fixture('cert6.pem')

    DSA_KEY = read_fixture('dsa_key.pem')

    # this CSR has unknown OIDs, which we should successfully parse out into Subject
    CSR_UNKNOWN_OID = read_fixture('unknown_oid.csr')


    #san cert from self-signed CA for langui.sh
    CERT_SAN = read_fixture('cert_san.pem')
    
    #Another san cert for langui.sh, but differentiating between the CN and 
    # SANs.
    CERT_SAN2 = read_fixture('cert_san2.pem')

    CERT_DER = read_fixture('cert1.der')

    SPKI = read_fixture('spkac.txt')

    SPKI_DER = read_fixture('spkac.der')

    SPKI_DSA = read_fixture('spkac_dsa.txt')

    CSR = read_fixture('csr1.pem')

    CSR_PUBLIC_KEY_MODULUS = read_fixture('csr1_public_key_modulus.txt')

    CSR_INVALID_SIGNATURE = read_fixture('csr_invalid_signature.pem')

    CSR_DER = read_fixture('csr1.der')

    CSR_NEWLINES = read_fixture('csr1_newlines.pem')

    CSR_NO_BEGIN_END = read_fixture('csr1_no_begin_end.pem')

    CSR_DSA = read_fixture('csr_dsa.pem')

    KEY_CSR = read_fixture('csr1_key.pem')

    KEY_CSR_DER = read_fixture('csr1_key.der')

    KEY_CSR_ENCRYPTED = read_fixture('csr1_key_encrypted_des3.pem')

    CSR2 = read_fixture('csr2.pem')

    KEY_CSR2 = read_fixture('csr2_key.pem')

    CSR3 = read_fixture('csr3.pem')

    CERT3 = read_fixture('cert3.pem')

    KEY3 = read_fixture('cert3_key.pem')

    KEY3_ENCRYPTED = read_fixture('cert3_key_des3.pem')

    CERT3_P12 = read_fixture('cert3.p12')

    CSR4_MULTIPLE_ATTRS = read_fixture('csr4.pem')

    KEY4_ENCRYPTED_DES3 = read_fixture('key4_encrypted_des3.pem')

    KEY4 = read_fixture('key4.pem')

    TEST_CA_CERT = read_fixture('test_ca.cer')
    TEST_CA_KEY  = read_fixture('test_ca.key')

    TEST_CA_OCSP_CERT = read_fixture('test_ca_ocsp.cer')
    TEST_CA_OCSP_KEY  = read_fixture('test_ca_ocsp.key')

    SECOND_CA_CERT = read_fixture('second_ca.cer')
    SECOND_CA_KEY  = read_fixture('second_ca.key')

    OCSP_TEST_CERT = read_fixture('ocsptest.r509.local.pem')
    OCSP_TEST_CERT2 = read_fixture('ocsptest2.r509.local.pem')

    STCA_OCSP_REQUEST  = read_fixture('stca_ocsp_request.der')
    STCA_OCSP_RESPONSE  = read_fixture('stca_ocsp_response.der')

    CRL_LIST_FILE = (FIXTURES_PATH+'crl_list_file.txt').to_s

    def self.test_ca_cert
        R509::Cert.new(:cert => TEST_CA_CERT, :key => TEST_CA_KEY)
    end

    def self.test_ca_server_profile
        R509::Config::CaProfile.new(
              :basic_constraints => "CA:FALSE",
              :key_usage => ["digitalSignature","keyEncipherment"],
              :extended_key_usage => ["serverAuth"],
              :certificate_policies => [
                    [
                        "policyIdentifier=2.16.840.1.12345.1.2.3.4.1",
                        "CPS.1=http://example.com/cps"
                    ]
                ]
        )

    end

    def self.test_ca_server_profile_with_subject_item_policy
        subject_item_policy = R509::Config::SubjectItemPolicy.new(
            "CN" => "required",
            "O" => "optional",
            "ST" => "required",
            "C" => "required",
            "OU" => "optional"
        )
        R509::Config::CaProfile.new(
            :basic_constraints => "CA:FALSE",
            :key_usage => ["digitalSignature","keyEncipherment"],
            :extended_key_usage => ["serverAuth"],
            :certificate_policies => [
                [
                    "policyIdentifier=2.16.840.1.12345.1.2.3.4.1",
                    "CPS.1=http://example.com/cps"
                ]
            ],
            :subject_item_policy => subject_item_policy
        )
    end

    def self.test_ca_subroot_profile
        R509::Config::CaProfile.new(
                  :basic_constraints => "CA:TRUE,pathlen:0",
                  :key_usage => ["keyCertSign","cRLSign"],
                  :extended_key_usage => [],
                  :certificate_policies => nil)
    end

    def self.test_ca_ocspsigner_profile
        R509::Config::CaProfile.new(
                  :basic_constraints => "CA:FALSE",
                  :key_usage => ["digitalSignature"],
                  :extended_key_usage => ["OCSPSigning"],
                  :certificate_policies => nil)
    end

    def self.second_ca_cert
        R509::Cert.new(:cert => SECOND_CA_CERT, :key => SECOND_CA_KEY)
    end

    def self.second_ca_server_profile
        R509::Config::CaProfile.new(
              :basic_constraints => "CA:FALSE",
              :key_usage => ["digitalSignature","keyEncipherment"],
              :extended_key_usage => ["serverAuth"],
              :certificate_policies => [
                    [
                        "policyIdentifier=2.16.840.1.12345.1.2.3.4.1",
                        "CPS.1=http://example.com/cps"
                    ]
                ]
        )

    end

    def self.second_ca_subroot_profile
        R509::Config::CaProfile.new(
                  :basic_constraints => "CA:TRUE,pathlen:0",
                  :key_usage => ["keyCertSign","cRLSign"],
                  :extended_key_usage => [],
                  :certificate_policies => nil)
    end


    # @return [R509::Config::CaConfig]
    def self.test_ca_config
        crl_list_sio = StringIO.new
        crl_list_sio.set_encoding("BINARY") if crl_list_sio.respond_to?(:set_encoding)
        crl_number_sio = StringIO.new
        crl_number_sio.set_encoding("BINARY") if crl_number_sio.respond_to?(:set_encoding)

        opts = {
          :ca_cert => test_ca_cert(),
          :cdp_location => 'URI:http://crl.domain.com/test_ca.crl',
          :ocsp_location => 'URI:http://ocsp.domain.com',
          :crl_list_file => crl_list_sio,
          :crl_number_file => crl_number_sio
        }
        ret = R509::Config::CaConfig.new(opts)

        ret.set_profile("server", self.test_ca_server_profile)
        ret.set_profile("subroot", self.test_ca_subroot_profile)
        ret.set_profile("ocspsigner", self.test_ca_ocspsigner_profile)
        ret.set_profile("server_with_subject_item_policy", self.test_ca_server_profile_with_subject_item_policy)

        ret
    end

    # @return [R509::Config::CaConfig] secondary config
    def self.second_ca_config
        opts = {
          :ca_cert => second_ca_cert(),
          :cdp_location => 'URI:http://crl.domain.com/test_ca.crl',
          :ocsp_location => 'URI:http://ocsp.domain.com'
        }
        ret = R509::Config::CaConfig.new(opts)

        ret.set_profile("server", self.second_ca_server_profile)
        ret.set_profile("subroot", self.second_ca_subroot_profile)

        ret
    end
end
