# A module for building an easy to use CA. Includes CSR, Certificate, and CRL support.
module R509
	autoload :Ca, 'r509/Ca.rb'
	autoload :Csr, 'r509/Csr.rb'
	autoload :Cert, 'r509/Cert.rb'
	autoload :Crl, 'r509/Crl.rb'
end
