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

  CERT_PUBLIC_KEY = read_fixture('cert1_public_key.pem')


  #san cert from self-signed CA for langui.sh
  CERT_SAN = read_fixture('cert_san.pem')

  CERT_DER = read_fixture('cert1.der')

  SPKAC = read_fixture('spkac.txt')

  CSR = read_fixture('csr1.pem')

  CSR_DER = read_fixture('csr1.der')

  KEY_CSR = read_fixture('csr1_key.pem')

  CSR2 = read_fixture('csr2.pem')

  KEY_CSR2 = read_fixture('csr2_key.pem')

  CSR3 = read_fixture('csr3.pem')

  CERT3 = read_fixture('cert3.pem')

  KEY3 = read_fixture('cert3_key.pem')

  CSR4_MULTIPLE_ATTRS = read_fixture('csr4.pem')

  KEY4_ENCRYPTED_DES3 = read_fixture('key4_encrypted_des3.pem')

  KEY4 = read_fixture('key4.pem')
end
