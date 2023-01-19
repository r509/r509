require 'spec_helper'
require 'pathname'
require 'r509/io_helpers'

# Contains constants and other values for testing purposes
module TestFixtures
  extend R509::IOHelpers

  FIXTURES_PATH = Pathname.new(__FILE__).dirname + "fixtures"

  def self.read_fixture(filename)
    read_data((FIXTURES_PATH + filename).to_s)
  end

  # Trustwave cert for langui.sh
  CERT = read_fixture('cert1.pem')

  CERT_INHIBIT = read_fixture('cert_inhibit.pem')
  CERT_POLICY_CONSTRAINTS = read_fixture('cert_policy_constraints.pem')
  CERT_NAME_CONSTRAINTS = read_fixture('cert_name_constraints.pem')

  # Trustwave root cert
  STCA_CERT = read_fixture('stca.pem')

  CERT_PUBLIC_KEY_MODULUS = read_fixture('cert1_public_key_modulus.txt')

  # cert without key usage
  CERT4 = read_fixture('cert4.pem')

  # cert with multiple EKU
  CERT5 = read_fixture('cert5.pem')

  # cert with DSA public key
  CERT6 = read_fixture('cert6.pem')

  CERT_EXPIRED = read_fixture("cert_expired.pem")

  CERT_NOT_YET_VALID = read_fixture("cert_not_yet_valid.pem")

  DSA_KEY = read_fixture('dsa_key.pem')

  # this CSR has unknown OIDs, which we should successfully parse out into Subject
  CSR_UNKNOWN_OID = read_fixture('unknown_oid.csr')

  # san cert from self-signed CA for langui.sh
  CERT_SAN = read_fixture('cert_san.pem')

  # Another san cert for langui.sh, but differentiating between the CN and
  # SANs.
  CERT_SAN2 = read_fixture('cert_san2.pem')

  CERT_DER = read_fixture('cert1.der')

  SPKI = read_fixture('spkac.txt')

  SPKI_DER = read_fixture('spkac.der')

  SPKI_DSA = read_fixture('spkac_dsa.txt')

  SPKI_DSA_NO_VERIFY = read_fixture('spkac_dsa_no_verify.txt')

  SPKI_EC = read_fixture('spkac_ec.txt')

  SPKI_RSA_NEWLINES = read_fixture('spkac_rsa_newlines.txt')

  CSR = read_fixture('csr1.pem')

  CSR_PUBLIC_KEY_MODULUS = read_fixture('csr1_public_key_modulus.txt')

  CSR_INVALID_SIGNATURE = read_fixture('csr_invalid_signature.pem')

  SPKI_INVALID_SIGNATURE = "MIIBOjCBpDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAnk0rEYEFZS0KaOq1xb4pJbWMuTFbji9a5GDjgw8jDQh3YS5968sXqmTZS9Vm0ctOmicUka0MOfSwlVEzvLLh/5Na7A8dreOrGI3Qck9AsAEfCBWACZ4hTOfm23rBQYsR9FkEhDAVUXZm2JBPZM38c5QVV37NNr2zCD+CIoXhCjMCAwEAARYAMA0GCSqGSIb3DQEBBQUAA4GBAENx9YXoEYTCOkC9SX4qQFmRgCTFhZVB6E+aAW20KIndAchIctegOR4mzCHAgizmvgmboevG9meKOVZJRWLucElIOnXBFV7BORsn9HP8Bhc1ct3wip2Bwp9wFPM8MS7FyA/Csyze8eKh5wedXWTmPqHMcoUz2QP0lSu1iRZGLRps"

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

  CSR_WILDCARD_NO_SAN = read_fixture('csr_wildcard_no_san.pem')

  KEY3_ENCRYPTED = read_fixture('cert3_key_des3.pem')

  CERT3_P12 = read_fixture('cert3.p12')

  CSR4_MULTIPLE_ATTRS = read_fixture('csr4.pem')

  KEY4_ENCRYPTED_DES3 = read_fixture('key4_encrypted_des3.pem')

  KEY4 = read_fixture('key4.pem')

  CERT_OCSP_NO_CHECK = read_fixture('cert_ocsp_no_check.pem')

  EC_KEY1 = read_fixture('ec_key1.pem')
  EC_KEY1_DER = read_fixture('ec_key1.der')
  EC_KEY1_ENCRYPTED = read_fixture('ec_key1_encrypted.pem')

  EC_CSR2_PEM = read_fixture('ec_csr2.pem')
  EC_CSR2_DER = read_fixture('ec_csr2.der')
  EC_KEY2 = read_fixture('ec_key2.pem')

  EC_EE_CERT = read_fixture("test_ca_ec_ee.cer")
  EC_EE_KEY = read_fixture("test_ca_ec_ee.key")

  DSA_CA_CERT = read_fixture('dsa_root.cer')
  DSA_CA_KEY = read_fixture('dsa_root.key')

  TEST_CA_EC_CERT = read_fixture('test_ca_ec.cer')
  TEST_CA_EC_KEY = read_fixture('test_ca_ec.key')

  TEST_CA_CERT = read_fixture('test_ca.cer')
  TEST_CA_KEY  = read_fixture('test_ca.key')

  TEST_CA_OCSP_CERT = read_fixture('test_ca_ocsp.cer')
  TEST_CA_OCSP_KEY  = read_fixture('test_ca_ocsp.key')

  TEST_CA_CRL_CERT = read_fixture('test_ca_crl.cer')
  TEST_CA_CRL_KEY  = read_fixture('test_ca_crl.key')

  TEST_CA_SUBROOT_CERT = read_fixture('test_ca_subroot.cer')
  TEST_CA_SUBROOT_KEY  = read_fixture('test_ca_subroot.key')

  # this chain contains 2 certs. root and OCSP delegate
  # in a prod environment you'd really only need the delegate
  # since the root would be present in the root store of the
  # client, but I wanted to test > 1
  TEST_CA_OCSP_CHAIN  = read_fixture('test_ca_ocsp_chain.txt')

  TEST_CA_OCSP_RESPONSE = read_fixture('test_ca_ocsp_response.der')

  TEST_CA_SUBROOT_OCSP_RESPONSE = read_fixture('test_ca_subroot_ocsp_response.der')

  SECOND_CA_CERT = read_fixture('second_ca.cer')
  SECOND_CA_KEY  = read_fixture('second_ca.key')

  OCSP_TEST_CERT = read_fixture('ocsptest.r509.local.pem')
  OCSP_TEST_CERT2 = read_fixture('ocsptest2.r509.local.pem')

  STCA_OCSP_REQUEST  = read_fixture('stca_ocsp_request.der')
  STCA_OCSP_RESPONSE  = read_fixture('stca_ocsp_response.der')

  CRL_LIST_FILE = (FIXTURES_PATH + 'crl_list_file.txt').to_s

  CRL_REASON = read_fixture("crl_with_reason.pem")

  HMACSHA512_SIG = read_fixture("hmacsha512.sig")
  HMACSHA1_SIG = read_fixture("hmacsha1.sig")

  CRL_LIST_SQLITE = read_fixture("crl_list.sql")
  def self.test_ca_cert
    R509::Cert.new(:cert => TEST_CA_CERT, :key => TEST_CA_KEY)
  end

  def self.test_ca_crl_delegate
    R509::Cert.new(:cert => TEST_CA_CRL_CERT, :key => TEST_CA_CRL_KEY)
  end

  def self.test_ca_ec_cert
    R509::Cert.new(:cert => TEST_CA_EC_CERT, :key => TEST_CA_EC_KEY)
  end

  def self.test_ca_dsa_cert
    R509::Cert.new(:cert => DSA_CA_CERT, :key => DSA_CA_KEY)
  end

  def self.test_ca_subroot_cert
    R509::Cert.new(:cert => TEST_CA_SUBROOT_CERT, :key => TEST_CA_SUBROOT_KEY)
  end

  def self.test_ca_server_profile
    R509::Config::CertProfile.new(
      :basic_constraints => R509::Cert::Extensions::BasicConstraints.new(:ca => false),
      :key_usage => R509::Cert::Extensions::KeyUsage.new(:value => ["digitalSignature", "keyEncipherment"]),
      :extended_key_usage => R509::Cert::Extensions::ExtendedKeyUsage.new(:value => ["serverAuth"]),
      :certificate_policies => R509::Cert::Extensions::CertificatePolicies.new(
        :value => [
          { :policy_identifier => "2.16.840.1.12345.1.2.3.4.1",
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
      )
    )
  end

  def self.test_ca_server_profile_with_subject_item_policy
    subject_item_policy = R509::Config::SubjectItemPolicy.new(
      "CN" => { :policy => "required" },
      "O" => { :policy => "optional" },
      "ST" => { :policy => "required" },
      "C" => { :policy => "required" },
      "OU" => { :policy => "optional" }
    )
    R509::Config::CertProfile.new(
      :basic_constraints => R509::Cert::Extensions::BasicConstraints.new(:ca => false),
      :key_usage => R509::Cert::Extensions::KeyUsage.new(:value => ["digitalSignature", "keyEncipherment"]),
      :extended_key_usage => R509::Cert::Extensions::ExtendedKeyUsage.new(:value => ["serverAuth"]),
      :certificate_policies => R509::Cert::Extensions::CertificatePolicies.new(
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
      ),
      :subject_item_policy => subject_item_policy
    )
  end

  def self.test_ca_subroot_profile
    R509::Config::CertProfile.new(
          :basic_constraints => { :ca => true, :path_length => 0 },
          :key_usage => { :value => ["keyCertSign", "cRLSign"] },
          :certificate_policies => nil)
  end

  def self.test_ca_ocspsigner_profile
    R509::Config::CertProfile.new(
          :basic_constraints => { :ca => false },
          :key_usage => { :value => ["digitalSignature"] },
          :extended_key_usage => { :value => ["OCSPSigning"] },
          :certificate_policies => nil)
  end

  # @return [R509::Config::CAConfig]
  def self.test_ca_config
    crl_list_sio = StringIO.new
    crl_list_sio.set_encoding("BINARY") if crl_list_sio.respond_to?(:set_encoding)
    crl_number_sio = StringIO.new
    crl_number_sio.set_encoding("BINARY") if crl_number_sio.respond_to?(:set_encoding)

    opts = {
      :ca_cert => test_ca_cert,
      :ocsp_start_skew_seconds => 3600,
      :ocsp_validity_hours => 48,
      :crl_list_file => crl_list_sio,
      :crl_number_file => crl_number_sio
    }
    ret = R509::Config::CAConfig.new(opts)

    ret.set_profile("server", self.test_ca_server_profile)
    ret.set_profile("subroot", self.test_ca_subroot_profile)
    ret.set_profile("ocspsigner", self.test_ca_ocspsigner_profile)
    ret.set_profile("server_with_subject_item_policy", self.test_ca_server_profile_with_subject_item_policy)

    ret
  end

  # @return [R509::Config::CAConfig]
  def self.test_ca_no_profile_config
    crl_list_sio = StringIO.new
    crl_list_sio.set_encoding("BINARY") if crl_list_sio.respond_to?(:set_encoding)
    crl_number_sio = StringIO.new
    crl_number_sio.set_encoding("BINARY") if crl_number_sio.respond_to?(:set_encoding)

    opts = {
      :ca_cert => test_ca_cert,
      :ocsp_start_skew_seconds => 3600,
      :ocsp_validity_hours => 48,
      :crl_list_file => crl_list_sio,
      :crl_number_file => crl_number_sio
    }
    R509::Config::CAConfig.new(opts)
  end

  def self.test_ca_ec_no_profile_config
    crl_list_sio = StringIO.new
    crl_list_sio.set_encoding("BINARY") if crl_list_sio.respond_to?(:set_encoding)
    crl_number_sio = StringIO.new
    crl_number_sio.set_encoding("BINARY") if crl_number_sio.respond_to?(:set_encoding)

    opts = {
      :ca_cert => test_ca_ec_cert,
      :ocsp_start_skew_seconds => 3600,
      :ocsp_validity_hours => 48,
      :crl_list_file => crl_list_sio,
      :crl_number_file => crl_number_sio
    }
    R509::Config::CAConfig.new(opts)
  end

  def self.test_ca_dsa_no_profile_config
    crl_list_sio = StringIO.new
    crl_list_sio.set_encoding("BINARY") if crl_list_sio.respond_to?(:set_encoding)
    crl_number_sio = StringIO.new
    crl_number_sio.set_encoding("BINARY") if crl_number_sio.respond_to?(:set_encoding)

    opts = {
      :ca_cert => test_ca_dsa_cert,
      :ocsp_start_skew_seconds => 3600,
      :ocsp_validity_hours => 48,
      :crl_list_file => crl_list_sio,
      :crl_number_file => crl_number_sio
    }
    R509::Config::CAConfig.new(opts)
  end
end
