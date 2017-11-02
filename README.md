# r509 [![Build Status](https://secure.travis-ci.org/r509/r509.png)](http://travis-ci.org/r509/r509) [![Coverage Status](https://coveralls.io/repos/r509/r509/badge.png?branch=master)](https://coveralls.io/r/r509/r509?branch=master)
r509 is a Ruby gem built using OpenSSL that is designed to ease management of a public key infrastructure. The r509 API facilitates easy creation of CSRs, signing of certificates, revocation (CRL/OCSP), and much more. Together with projects like [r509-ocsp-responder](https://github.com/r509/r509-ocsp-responder) and [r509-ca-http](https://github.com/r509/r509-ca-http) it is intended to be a complete [RFC 5280](http://www.ietf.org/rfc/rfc5280.txt)-compliant certificate authority for use in production environments.

## Why?
Certificates are hard, and the Ruby OpenSSL APIs aren't easy to use (because they hew closely to OpenSSL itself). Additionally, as SSL/TLS has aged a variety of best practices and workarounds around certificate issuance have grown up around it that are not easy to discover. r509 is an attempt to build a straightforward API that allows you to do things as simple as parsing a certificate all the way up to operating an entire certificate authority.

## Requirements

r509 requires Ruby 2.0.0+ compiled with OpenSSL and YAML support (this is a typical default). It is recommended that you compile Ruby against OpenSSL 1.0.1+ (with elliptic curve support enabled). Red Hat-derived distributions prior to RHEL/CentOS 6.5 ship with EC disabled in OpenSSL, so if you need EC support you will need to recompile.

## Installation
You can install via rubygems with ```gem install r509```

To install the gem from your own clone (you will need to satisfy the dependencies via ```bundle install``` or other means):

```bash
rake gem:build
rake gem:install
```

## Documentation
There is documentation available for every method and class in r509 available via yardoc. If you installed via gem it should be pre-generated in the doc directory. If you cloned this repo, just type ```rake yard``` with the yard gem installed. You will also need the redcarpet and github-markup gems to properly parse the README.md.

## Changelog

### 1.0.1

* Support Rubies compiled against OpenSSL 1.1.0.

## Support
You can [file bugs](https://github.com/r509/r509/issues) to get support from the community.

## Running Tests/Building Gem
If you want to run the tests for r509 you'll need rspec. Additionally, you should install simplecov and yard for running the code coverage and documentation tasks in the Rakefile. ```rake -T``` for a complete list of rake tasks available.

## Continuous Integration
We run continuous integration tests (using Travis-CI) against 2.2, 2.3, and 2.4. 1.8.7 is no longer a supported configuration due to issues with its elliptic curve methods. 0.8.1 was the last official r509 release with 1.8.7 support.

## Executables

r509 ships with a binary named ```r509``` that can generate CSRs, keys, and create self-signed certificates. Type ```r509 -h``` to see a list of options.

## Basic Certificate Authority Tutorial
[This guide](http://langui.sh/2012/11/02/building-a-ca-r509-howto/) provides instructions on building a basic CA using r509, [r509-ca-http](https://github.com/r509/r509-ca-http), and [r509-ocsp-responder](https://github.com/r509/r509-ocsp-responder). In it you will learn how to create a root, set up the configuration profiles, issue certificates, revoke certificates, and see responses from an OCSP responder.

## Quick Start
### CSR
To generate a 2048-bit RSA CSR

```ruby
csr = R509::CSR.new(
  :subject => [
    ['CN','somedomain.com'],
    ['O','My Org'],
    ['L','City'],
    ['ST','State'],
    ['C','US']
  ]
)
# alternately
csr = R509::CSR.new(
  :subject => {
    :CN => 'somedomain.com',
    :O => 'My Org',
    :L => 'City',
    :ST => 'State',
    :C => 'US'
  }
)

```

Another way to build the subject:

```ruby
subject = R509::Subject.new
subject.CN="somedomain.com"
subject.O="My Org"
subject.L="City"
subject.ST="State"
subject.C="US"
csr = R509::CSR.new( :subject => subject )
```

To load an existing CSR (without private key)

```ruby
csr_pem = File.read("/path/to/csr")
csr = R509::CSR.new(:csr => csr_pem)
# or
csr = R509::CSR.load_from_file("/path/to/csr")
```

To create a new CSR from the subject of a certificate

```ruby
cert_pem = File.read("/path/to/cert")
csr = R509::CSR.new(:cert => cert_pem)
```

To create a CSR with SAN names

```ruby
csr = R509::CSR.new(
  :subject => [['CN','something.com']],
  :san_names => ["something2.com","something3.com"]
)
```

### Cert
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

### PrivateKey
Generate a 1536-bit RSA key

```ruby
key = R509::PrivateKey.new(:type => "RSA", :bit_length => 1536)
```

Encrypt a private key

```ruby
key = R509::PrivateKey.new(:type => "RSA", :bit_length => 2048)
encrypted_pem = key.to_encrypted_pem("aes256","my-password")
# or write it to disk
key.write_encrypted_pem("/tmp/path","aes256","my-password")
```

#### Load Hardware Engines in PrivateKey

The engine you want to load must already be available to OpenSSL. How to compile/install OpenSSL engines is outside the scope of this document.

```ruby
engine = R509::Engine.instance.load(:so_path => "/usr/lib64/openssl/engines/libchil.so", :id => "chil")
key = R509::PrivateKey(
  :engine => engine,
  :key_name => "my_key_name"
)
```

You can then use this key for signing.

### SPKI/SPKAC
To generate a 2048-bit RSA SPKI

```ruby
key = R509::PrivateKey.new(:type => "RSA", :bit_length => 1024)
spki = R509::SPKI.new(:key => key)
```

### Self-Signed Certificate
To create a self-signed certificate

```ruby
not_before = Time.now.to_i
not_after = Time.now.to_i+3600*24*7300
csr = R509::CSR.new(
  :subject => [['C','US'],['O','r509 LLC'],['CN','r509 Self-Signed CA Test']]
)
# if you do not pass :extensions it will add basic constraints CA:TRUE, a SubjectKeyIdentifier, and an AuthorityKeyIdentifier
cert = R509::CertificateAuthority::Signer.selfsign(
  :csr => csr,
  :not_before => not_before,
  :not_after => not_after
)
```

### Config

#### CAConfig
Create a basic CAConfig object

```ruby
cert_pem = File.read("/path/to/cert")
key_pem = File.read("/path/to/key")
cert = R509::Cert.new(
  :cert => cert_pem,
  :key => key_pem
)
config = R509::Config::CAConfig.new(
  :ca_cert => cert
)
```

#### SubjectItemPolicy
Subject Item Policy allows you to define what subject fields are allowed in a certificate. Required means that field *must* be supplied, optional means it will be encoded if provided, and match means the field must be present and must match the value specified. The keys must match OpenSSL's short names.


```ruby
sip = 509::Config::SubjectItemPolicy.new(
  "CN" => {:policy => "required"},
  "O" => {:policy => "optional"},
  "OU" => {:policy => "match", :value => "Engineering" }
)
```

#### CertProfile
Certificate profiles hold extensions you want to put in a certificate, allowed/default message digests, and subject item policies. You can build them programmatically or load them via YAML. When building programmatically you can also serialize to YAML for future use. This is the preferred way to build the YAML.

The CertProfile object can either take objects or the hash that would build those objects.

Objects:

```ruby
profile = R509::Config::CertProfile.new(
  :basic_constraints => R509::Cert::Extensions::BasicConstraints.new(
    :ca => false
  ),
  :key_usage => R509::Cert::Extensions::KeyUsage.new(
    :value => ['digitalSignature','keyEncipherment']
  ),
  :extended_key_usage => R509::Cert::Extensions::ExtendedKeyUsage.new(
    :value => ['serverAuth','clientAuth']
  ),
  :authority_info_access => R509::Cert::Extensions::AuthorityInfoAccess.new(
    :ocsp_location => [{:type => 'URI', :value => 'http://ocsp.myca.net'}]
  ),
  :certificate_policies => R509::Cert::Extensions::CertificatePolicies.new(
    :value => [{:policy_identifier => '1.23.3.4.4.5.56'}]
  ),
  :crl_distribution_points => R509::Cert::Extensions::CRLDistributionPoints.new(
    :value => [{:type => 'URI', :value => 'http://crl.myca.net/ca.crl'}]
  ),
  :inhibit_any_policy => R509::Cert::Extensions::InhibitAnyPolicy.new(
    :value => 0
  ),
  :name_constraints => R509::Cert::Extensions::NameConstraints.new(
    :permitted => [{:type => 'dirName', :value => { :CN => 'test' } }]
  ),
  :ocsp_no_check => R509::Cert::Extensions::OCSPNoCheck.new(:value => true),
  :policy_constraints => R509::Cert::Extensions::PolicyConstraints.new(
    :require_explicit_policy=> 1
  ),
  :subject_item_policy => R509::Config::SubjectItemPolicy.new(
    "CN" => {:policy => "required"},
    "O" => {:policy => "optional"},
    "OU" => {:policy => "match", :value => "Engineering" }
  ),
  :default_md => "SHA256",
  :allowed_mds => ["SHA256","SHA512"]
)
```

Hashes:

```ruby
profile = R509::Config::CertProfile.new(
  :basic_constraints => {:ca => false},
  :key_usage => { :value => ["digitalSignature","keyEncipherment"] },
  :extended_key_usage => { :value => ["serverAuth"] },
  :certificate_policies => [
    { :policy_identifier => "2.16.840.1.99999.21.234",
      :cps_uris => ["http://example.com/cps","http://haha.com"],
      :user_notices => [ { :explicit_text => "this is a great thing", :organization => "my org", :notice_numbers => [1,2,3] } ]
    }
  ],
  :subject_item_policy => nil,
  :crl_distribution_points => {:value => [{ :type => "URI", :value => "http://crl.myca.net/ca.crl" }] },
  :authority_info_access => {
    :ocsp_location => [{ :type => "URI", :value => "http://ocsp.myca.net" }],
    :ca_issuers_location => [{ :type => "URI", :value => "http://www.myca.net/some_ca.cer" }]
  }
)
# CAConfig object from above assumed
config.set_profile("server",profile)
```

#### CAConfigPool
Multiple CAConfigs can be loaded via CAConfigPool

```ruby
# from objects
pool = R509::Config::CAConfigPool.new("my_ca" => config, "another_ca" => another_config)
# from yaml
pool = R509::Config::CAConfigPool.from_yaml("certificate_authorities", "config_pool.yaml")
```

Example (Minimal) Config Pool YAML

```yaml
certificate_authorities:
  test_ca:
    ca_cert:
      cert: test_ca.cer
      key: test_ca.key
  second_ca:
    ca_cert:
      cert: second_ca.cer
      key: second_ca.key
```

#### Building YAML
You can serialize a CAConfig (or CAConfigPool) via ```#to_yaml```. The output of the YAML will vary depending upon what data you have supplied to the object, but the output does require the following manual configuration:

* Add paths to the requested files where you see add_path (or change the options entirely. See the YAML config section below)
* Define a name for your config and put the YAML inside it. In the example below the config has been named example_ca

```yaml
example_ca:
  # the following is the output of #to_yaml
  ca_cert:
    cert: <add_path>
    key: <add_path>
  ocsp_start_skew_seconds: 3600
  ocsp_validity_hours: 168
  crl_md: SHA256
  profiles:
    profile:
      subject_item_policy:
        CN:
          :policy: required
        O:
          :policy: required
        L:
          :policy: required
        OU:
          :policy: optional
      default_md: SHA512
```

### CertificateAuthority::Signer (sans CertProfile)

Sign a CSR

```ruby
csr = R509::CSR.new(
  :subject => {
    :CN => 'somedomain.com',
    :O => 'My Org',
    :L => 'City',
    :ST => 'State',
    :C => 'US'
  }
)
# assume config from yaml load above
ca = R509::CertificateAuthority::Signer.new(config)
ext = []
# you can add extensions in an array. See R509::Cert::Extensions::*
ext << R509::Cert::Extensions::BasicConstraints.new(:ca => false)

cert = ca.sign(
  :csr => csr,
  :extensions => ext
)
```

Override a CSR's subject or SAN names when signing

```ruby
csr = R509::CSR.new(
  :subject => {
    :CN => 'somedomain.com',
    :O => 'My Org',
    :L => 'City',
    :ST => 'State',
    :C => 'US'
  }
)
subject = csr.subject.dup
san_names = [{:type=> 'DNS', :value => "domain2.com"},{:type => 'IP', :value => "128.128.128.128"}]
subject.common_name = "newdomain.com"
subject.organization = "Org 2.0"
ext = []
ext << R509::Cert::Extensions::BasicConstraints.new(:ca => false)
ext << R509::Cert::Extensions::SubjectAlternativeName.new(:value => san_names)
# assume config from yaml load above
ca = R509::CertificateAuthority::Signer.new(config)
cert = ca.sign(
  :csr => csr,
  :subject => subject,
  :extensions => ext
)
```

Sign an SPKI/SPKAC object

```ruby
key = R509::PrivateKey.new(:type => "RSA", :bit_length => 2048)
spki = R509::SPKI.new(:key => key)
# SPKI objects do not contain subject or san name data so it must be specified
subject = R509::Subject.new
subject.CN = "mydomain.com"
subject.L = "Locality"
subject.ST = "State"
subject.C = "US"
san_names = [{:type=> 'DNS', :value => "domain2.com"},{:type => 'IP', :value => "128.128.128.128"}]
ext = []
ext << R509::Cert::Extensions::BasicConstraints.new(:ca => false)
ext << R509::Cert::Extensions::SubjectAlternativeName.new(:value => san_names)
# assume config from yaml load above
ca = R509::CertificateAuthority::Signer.new(config)
cert = ca.sign(
  :spki => spki,
  :subject => subject,
  :extensions => ext
)

```

### CertificateAuthority::OptionsBuilder
The OptionsBuilder takes in a CAConfig with CertProfiles. You then call ```#build_and_enforce``` to have it create a hash that can be passed to ```R509::CertificateAuthority::Signer#sign```. The OptionsBuilder is responsible for enforcing restrictions on subject DN (via SubjectItemPolicy), determing allowed message digest, and adding a profile's extensions.

```ruby
# assume config from yaml load above
csr = R509::CSR.new(
  :subject => {
    :CN => 'somedomain.com',
    :O => 'My Org',
    :L => 'City',
    :ST => 'State',
    :C => 'US'
  }
)
builder = R509::CertificateAuthority::OptionsBuilder.new(config)
scrubbed_data = builder.build_and_enforce(
  :csr => csr,
  :profile_name => "server",
  :subject => {:CN => 'rewritten.com'},
  :san_names => ['r509.org'],
  :message_digest => 'SHA256'
)
# this returns a hash with keys :csr/:pki, :subject, :extensions, and :message_digest
signer = R509::CertificateAuthority::Signer.new(config)
cert = signer.sign(scrubbed_data)

```

You can optionally supply an array of R509::Cert::Extensions::* objects to the builder via the ```:extensions``` key. These will be merged with the extensions from the profile. If an extension in this array is also present in the profile, *the supplied extension will override the profile*.

```ruby
# assume pre-existing config and csr from above
builder = R509::CertificateAuthority::OptionsBuilder.new(config)
scrubbed_data = builder.build_and_enforce(
  :csr => csr,
  :profile_name => "server",
  :subject => {:CN => 'rewritten.com'},
  :san_names => ['r509.org'],
  :message_digest => 'SHA256',
  :extensions => [R509::Cert::Extensions::BasicConstraints.new(:ca => true)]
)
```

### CRL Administration
The CRL administrator object takes an ```R509::Config::CAConfig``` and an optional ```R509::CRL::ReaderWriter``` subclass. By default it will use an ```R509::CRL::FileReaderWriter``` class that assumes the presence of ```crl_number_file``` and ```crl_list_file``` in the CAConfig.

```ruby
admin = R509::CRL::Administrator.new(config)
```

#### Revoking a certificate
To revoke a certificate and generate a new CRL

```ruby
admin.revoke_cert(serial)
crl = admin.generate_crl
```

This revokes on the root configured by the CAConfig that was passed into the Administrator constructor.

### OID Mapping

Register one

```ruby
R509::OIDMapper.register("1.3.5.6.7.8.3.23.3","short_name","optional_long_name")
```

Register in batch

```ruby
R509::OIDMapper.batch_register([
  {:oid => "1.3.5.6.7.8.3.23.3", :short_name => "short_name", :long_name => "optional_long_name"},
  {:oid => "1.3.5.6.7.8.3.23.5", :short_name => "another_name"}
])
```

### Alternate Key Algorithms
In addition to the default RSA objects that are created above, r509 supports DSA and elliptic curve (EC). EC support is present only if Ruby has been linked against a version of OpenSSL compiled with EC enabled. This excludes Red Hat-based distributions at this time (unless you build it yourself). Take a look at the documentation for R509::PrivateKey, R509::Cert, and R509::CSR to see how to create DSA and EC types. You can test if elliptic curve support is available in your Ruby with:

```ruby
R509.ec_supported?
```

#### NIST Recommended Elliptic Curves
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


## Created by...
__Paul Kehrer__ ([Twitter](https://twitter.com/reaperhulk) | [GitHub](https://github.com/reaperhulk))

## Contributors
* [Sean Schulte](https://github.com/sirsean)
* [Mike Ryan](https://github.com/justfalter)
* [Chris Woodbury](https://github.com/woodbusy)

## License
See the LICENSE file. Licensed under the Apache 2.0 License.

##[YAML Documentation](YAML.md)
