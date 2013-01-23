#r509 [![Build Status](https://secure.travis-ci.org/reaperhulk/r509.png)](http://travis-ci.org/reaperhulk/r509)
r509 is a wrapper for various OpenSSL functions to allow easy creation of CSRs, signing of certificates, and revocation via CRL. Together with projects like [r509-ocsp-responder](https://github.com/reaperhulk/r509-ocsp-responder) and [r509-ca-http](https://github.com/sirsean/r509-ca-http) it is intended to be a complete certificate authority for use in production environments.

##Requirements/Installation

r509 requires the Ruby OpenSSL bindings as well as yaml support (present by default in modern Ruby builds).
To install the gem: ```gem install r509-(version).gem```

##Running Tests/Building Gem
If you want to run the tests for r509 you'll need rspec. Additionally, you may want to install rcov/simplecov (ruby 1.8/1.9 respectively) and yard for running the code coverage and documentation tasks in the Rakefile. ```rake -T``` for a complete list of rake tasks available.

##Continuous Integration
We run continuous integration tests (using Travis-CI) against 1.8.7, 1.9.3, 2.0.0, ree, ruby-head, and rubinius(rbx) 2.0 in 1.9 mode.

##Executable

Inside the gem there is a binary named ```r509```. Type ```r509 -h``` to see a list of options.

##Usage
###CSR
To generate a 2048-bit RSA CSR

```ruby
csr = R509::Csr.new(
  :subject => [
    ['CN','somedomain.com'],
    ['O','My Org'],
    ['L','City'],
    ['ST','State'],
    ['C','US']
  ]
)
```

To load an existing CSR (without private key)

```ruby
csr_pem = File.read("/path/to/csr")
csr = R509::Csr.new(:csr => csr_pem)
# or
csr = R509::Csr.load_from_file("/path/to/csr")
```

To create a new CSR from the subject of a certificate

```ruby
cert_pem = File.read("/path/to/cert")
csr = R509::Csr.new(:cert => cert_pem)
```

To create a CSR with SAN names

```ruby
csr = R509::Csr.new(
  :subject => [['CN','something.com']],
  :san_names => ["something2.com","something3.com"]
)
```

###Cert
To load an existing certificate

```ruby
cert_pem = File.read("/path/to/cert")
cert = R509::Cert.new(:cert => cert_pem)
# or
cert = R509::Cert.load_from_file("/path/to/cert")
```

Load a cert and key

```ruby
cert_pem = File.read("/path/to/cert")
key_pem = File.read("/path/to/key")
cert = R509::Cert.new(
  :cert => cert_pem,
  :key => key_pem
)
```

Load an encrypted private key

```ruby
cert_pem = File.read("/path/to/cert")
key_pem = File.read("/path/to/key")
cert = R509::Cert.new(
  :cert => cert_pem,
  :key => key_pem,
  :password => "private_key_password"
)
```

Load a PKCS12 file

```ruby
pkcs12_der = File.read("/path/to/p12")
cert = R509::Cert.new(
  :pkcs12 => pkcs12_der,
  :password => "password"
)
```

###Self-Signed Certificate
To create a self-signed certificate

```ruby
not_before = Time.now.to_i
not_after = Time.now.to_i+3600*24*7300
csr = R509::Csr.new(
  :subject => [['C','US'],['O','r509 LLC'],['CN','r509 Self-Signed CA Test']]
)
ca = R509::CertificateAuthority::Signer.new
cert = ca.selfsign(
  :csr => csr,
  :not_before => not_before,
  :not_after => not_after
)
```

###Config

Create a basic CaConfig object

```ruby
cert_pem = File.read("/path/to/cert")
key_pem = File.read("/path/to/key")
cert = R509::Cert.new(
  :cert => cert_pem,
  :key => key_pem
)
config = R509::Config::CaConfig.new(
  :ca_cert => cert
)
```

Add a signing profile named "server" (CaProfile) to a config object

```ruby
profile = R509::Config::CaProfile.new(
  :basic_constraints => "CA:FALSE",
  :key_usage => ["digitalSignature","keyEncipherment"],
  :extended_key_usage => ["serverAuth"],
  :certificate_policies => [ ["policyIdentifier=2.16.840.1.999999999.1.2.3.4.1", "CPS.1=http://example.com/cps"] ],
  :subject_item_policy => nil
)
# config object from above assumed
config.set_profile("server",profile)
```

Set up a subject item policy (required/optional). The keys must match OpenSSL's shortnames!

```ruby
profile = R509::Config::CaProfile.new(
  :basic_constraints => "CA:FALSE",
  :key_usage => ["digitalSignature","keyEncipherment"],
  :extended_key_usage => ["serverAuth"],
  :certificate_policies => [ ["policyIdentifier=2.16.840.1.999999999.1.2.3.4.1", "CPS.1=http://example.com/cps"] ],
  :subject_item_policy => {
    "CN" => "required",
    "O" => "optional"
  }
)
# config object from above assumed
config.set_profile("server",profile)
```

Load CaConfig + Profile from YAML

```ruby
config = R509::Config::CaConfig.from_yaml("test_ca", "config_test.yaml")
```

Example YAML (more options are supported than this example)

```yaml
test_ca: {
  ca_cert: {
    cert: '/path/to/test_ca.cer',
    key: '/path/to/test_ca.key'
  },
  crl_list: "crl_list_file.txt",
  crl_number: "crl_number_file.txt",
  cdp_location: 'URI:http://crl.domain.com/test_ca.crl',
  crl_validity_hours: 168, #7 days
  ocsp_location: 'URI:http://ocsp.domain.com',
  message_digest: 'SHA1', #SHA1, SHA256, SHA512 supported. MD5 too, but you really shouldn't use that unless you have a good reason
  profiles: {
    server: {
      basic_constraints: "CA:FALSE",
      key_usage: [digitalSignature,keyEncipherment],
      extended_key_usage: [serverAuth],
      certificate_policies: [ [ "policyIdentifier=2.16.840.1.9999999999.1.2.3.4.1", "CPS.1=http://example.com/cps"] ],
      subject_item_policy: {
        "CN" : "required",
        "O" : "optional",
        "ST" : "required",
        "C" : "required",
        "OU" : "optional" }
    }
  }
}
```

Load multiple CaConfigs using a CaConfigPool

```ruby
pool = R509::Config::CaConfigPool.from_yaml("certificate_authorities", "config_pool.yaml")
```

Example (Minimal) Config Pool YAML

```yaml
certificate_authorities: {
  test_ca: {
    ca_cert: {
      cert: 'test_ca.cer',
      key: 'test_ca.key'
    }
  },
  second_ca: {
    ca_cert: {
      cert: 'second_ca.cer',
      key: 'second_ca.key'
    }
  }
}
```

###CertificateAuthority

Sign a CSR

```ruby
csr = R509::Csr.new(
  :subject => [
    ['CN','somedomain.com'],
    ['O','My Org'],
    ['L','City'],
    ['ST','State'],
    ['C','US']
  ]
)
# assume config from yaml load above
ca = R509::CertificateAuthority::Signer.new(config)
cert = ca.sign(
  :profile_name => "server",
  :csr => csr
)
```

Override a CSR's subject or SAN names when signing

```ruby
csr = R509::Csr.new(
  :subject => [
    ['CN','somedomain.com'],
    ['O','My Org'],
    ['L','City'],
    ['ST','State'],
    ['C','US']
  ]
)
data_hash = csr.to_hash
data_hash[:san_names] = ["sannames.com","domain2.com"]
data_hash[:subject]["CN"] = "newdomain.com"
data_hash[:subject]["O"] = "Org 2.0"
# assume config from yaml load above
ca = R509::CertificateAuthority::Signer.new(config)
cert = ca.sign(
  :profile_name => "server",
  :csr => csr,
  :data_hash => data_hash
)
```

###Load Hardware Engines

The engine you want to load must already be available to OpenSSL. How to compile/install OpenSSL engines is outside the scope of this document.

```ruby
OpenSSL::Engine.load("engine_name")
engine = OpenSSL::Engine.by_id("engine_name")
key = R509::PrivateKey(
  :engine => engine,
  :key_name => "my_key_name"
)
```

You can then use this key for signing.


###OID Mapping

Register one

```ruby
R509::OidMapper.register("1.3.5.6.7.8.3.23.3","short_name","optional_long_name")
```

Register in batch

```ruby
R509::OidMapper.batch_register([
  {:oid => "1.3.5.6.7.8.3.23.3", :short_name => "short_name", :long_name => "optional_long_name"},
  {:oid => "1.3.5.6.7.8.3.23.5", :short_name => "another_name"}
])
```

###Alternate Key Algorithms
In addition to the default RSA objects that are created above, r509 supports DSA and elliptic curve (EC). EC support is present only if Ruby has been linked against a version of OpenSSL compiled with EC enabled. This excludes Red Hat-based distributions at this time (unless you build it yourself). Take a look at the documentation for R509::PrivateKey, R509::Cert, and R509::Csr to see how to create DSA and EC types.

####NIST Recommended Elliptic Curves
These curves are set via ```:curve_name```. The system defaults to using ```secp384r1```

 * secp224r1 -- NIST/SECG curve over a 224 bit prime field
 * secp384r1 -- NIST/SECG curve over a 384 bit prime field
 * secp521r1 -- NIST/SECG curve over a 521 bit prime field
 * prime192v1 -- NIST/X9.62/SECG curve over a 192 bit prime field
 * sect163k1 -- NIST/SECG/WTLS curve over a 163 bit binary field
 * sect163r2 -- NIST/SECG curve over a 163 bit binary field
 * sect233k1 -- NIST/SECG/WTLS curve over a 233 bit binary field
 * sect233r1 -- NIST/SECG/WTLS curve over a 233 bit binary field
 * sect283k1 -- NIST/SECG curve over a 283 bit binary field
 * sect283r1 -- NIST/SECG curve over a 283 bit binary field
 * sect409k1 -- NIST/SECG curve over a 409 bit binary field
 * sect409r1 -- NIST/SECG curve over a 409 bit binary field
 * sect571k1 -- NIST/SECG curve over a 571 bit binary field
 * sect571r1 -- NIST/SECG curve over a 571 bit binary field

##Documentation

There is (relatively) complete documentation available for every method and class in r509 available via yardoc. If you installed via gem it should be pre-generated in the doc directory. If you cloned this repo, just type ```rake yard``` with the yard gem installed. You will also need the redcarpet and github-markup gems to properly parse the Readme.md.

##Created by...
[Paul Kehrer](https://github.com/reaperhulk)

##Thanks to...
* [Sean Schulte](https://github.com/sirsean)
* [Mike Ryan](https://github.com/justfalter)

##License
See the LICENSE file. Licensed under the Apache 2.0 License.

#YAML Config Options
r509 configs are nested hashes of key:values that define the behavior of each CA. See r509.yaml for a full example config.

##ca\_name
###ca\_cert
This hash defines the certificate + key that will be used to sign for the ca\_name. Depending on desired configuration various elements are optional. You can even supply just __cert__ (for example, if you are using an ocsp\_cert hash and only using the configured CA for OCSP responses)

* cert (cannot use with pkcs12)
* key (cannot use with key)
* engine (optional, cannot be used with key or pkcs12)
* key\_name (required when using engine)
* pkcs12 (optional, cannot be used with key or cert)
* password (optional, used for pkcs12 or passworded private key)

###ocsp\_cert
This hash defines the certificate + key that will be used to sign for OCSP responses. OCSP responses cannot be directly created with r509, but require the ancillary gem [r509-ocsp-responder](https://github.com/reaperhulk/r509-ocsp-responder). This hash is optional and if not provided r509 will automatically use the ca\_cert as the OCSP certificate.

* cert (cannot use with pkcs12)
* key (cannot use with key)
* engine (optional, cannot be used with key or pkcs12)
* key\_name (required when using engine)
* pkcs12 (optional, cannot be used with key or cert)
* password (optional, used for pkcs12 or passworded private key)

###cdp\_location
The CRL distribution point for certificates issued from this CA.

Example: 'URI:http://crl.r509.org/myca.crl'

###crl\_list
The path on the filesystem of the list of revoked certificates for this CA.

Example: '/path/to/my\_ca\_crl\_list.txt'

###crl\_number
The path on the filesystem of the current CRL number for this CA.

Example: '/path/to/my\_ca\_crl\_number.txt'

###crl\_validity\_hours
Integer hours for CRL validity.

###ocsp\_location
The OCSP AIA extension value for certificates issued from this CA.

Example: 'URI:http://ocsp.r509.org'

###ocsp\_chain
An optional path to a concatenated text file of PEMs that should be attached to OCSP responses

###ocsp\_validity\_hours
Integer hours for OCSP response validity.

###ocsp\_start\_skew\_seconds
Integer seconds to skew back the "thisUpdate" field. This prevents issues where the OCSP responder signs a response and the client rejects it because the response is "not yet valid" due to slight clock synchronization problems.

###message\_digest
String value of the message digest to use for signing (both CRL and certificates). Allowed values are:

* SHA1 (default)
* SHA256
* SHA512
* MD5 (Don't use this unless you have a really, really good reason. Even then, you shouldn't)

###profiles
Each CA can have an arbitrary number of issuance profiles (with arbitrary names). For example, a CA named __test\_ca__ might have 3 issuance profiles: server, email, clientserver. Each of these profiles then has a set of options that define the encoded data in the certificate for that profile. If no profiles are defined the root cannot issue certs, but can still issue CRLs.

####basic\_constraints
All basic constraints are encoded with the critical bit set to true. In general you should only pass "CA:TRUE" (for an issuing CA) or "CA:FALSE" for everything else with this flag.

####key\_usage
An array of strings that conform to the OpenSSL naming scheme for available key usage OIDs. TODO: Document whether arbitrary OIDs can be passed here.

* digitalSignature
* nonRepudiation
* keyEncipherment
* dataEncipherment
* keyAgreement
* keyCertSign
* cRLSign
* encipherOnly
* decipherOnly

####extended\_key\_usage
An array of strings that conform to the OpenSSL naming scheme for available EKU OIDs. The following list of allowed shortnames is taken from the OpenSSL docs. Depending on your OpenSSL version there may be more than this list.

* serverAuth
* clientAuth
* codeSigning
* emailProtection
* OCSPSigning
* timeStamping
* msCodeInd
* msCodeCom
* msCTLSign
* msSGC
* msEFS
* nsSGC

####certificate\_policies
An array of arrays containing policy identifiers and CPS URIs. For example:

```yaml
[ [ "policyIdentifier=2.16.840.1.9999999.1.2.3.4.2","CPS.1=http://r509.org/cps" ] ]
```

or

```yaml
[ ["policyIdentifier=2.16.840.1.999999.0"], [ "policyIdentifier=2.16.840.1.9999999.1.2.3.4.2","CPS.1=http://r509.org/cps" ] ]
```

####subject\_item\_policy
Hash of required/optional subject items. These must be in OpenSSL shortname format. If subject\_item\_policy is excluded from the profile then all subject items will be used. If it is included, __only items listed in the policy will be copied to the certificate__.
Example:

```yaml
CN : "required",
O: "required",
OU: "optional",
ST: "required",
C: "required",
L: "required",
emailAddress: "optional"
```

If you use the R509::OidMapper you can create new shortnames that are allowed within this directive.
