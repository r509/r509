$:.unshift File.expand_path("../../lib", __FILE__)
$:.unshift File.expand_path("../", __FILE__)
require 'r509.rb'
require 'test_vars.rb'
require 'rspec'

describe R509::Crl do
	it "generates a crl and returns pem from an existing revocation list" do
		crl = R509::Crl.new('test_ca')
		crl.generate_crl
		crl.to_pem.should match(/BEGIN X509 CRL/)
	end
	it "returns der on to_der" do
		crl = R509::Crl.new('test_ca')
		crl.generate_crl
		crl.to_der.should_not == ''
	end
	it "adds a cert to the revocation list" do
		crl = R509::Crl.new('test_ca')
		crl.revoke_cert(383834832)
		crl.generate_crl.should match(/BEGIN X509 CRL/)
		found = false
		crl.revoked_list.each { |item| 
			if item['serial'] == 383834832 then
				found = true
			end	
		}
		found.should == true
	end
	it "removes a cert from the revocation list" do
		crl = R509::Crl.new('test_ca')
		crl.unrevoke_cert(383834832)
		crl.generate_crl
		found = false
		crl.revoked_list.each { |item| 
			if item['serial'] == 383834832 then
				found = true
			end	
		}
		found.should == false
	end
	it "sets validity period properly through the setter" do
		crl = R509::Crl.new('test_ca')
		crl.validity_hours = 2
		now = Time.at Time.now.to_i
		crl.generate_crl
		crl.next_update.should == (now+2*3600)
	end
	it "sets validity via yaml" do
		crl = R509::Crl.new('test_ca')
		now = Time.at Time.now.to_i
		crl.generate_crl
		crl.next_update.should == (now+168*3600) #default 168 hours (7 days)
	end
	it "has a last_update time" do
		crl = R509::Crl.new('test_ca')
		now = Time.at Time.now.to_i
		crl.generate_crl
		crl.last_update.should == now
	end
	it "writes to pem (improve me)" do
		crl = R509::Crl.new('test_ca')
		crl.generate_crl
		crl.write_pem('/tmp/crl')
		File.read('/tmp/crl').should_not == ''
		File.delete('/tmp/crl')
	end
	it "writes to der (improve me)" do
		crl = R509::Crl.new('test_ca')
		crl.generate_crl
		crl.write_der('/tmp/crl')
		File.read('/tmp/crl').should_not == ''
		File.delete('/tmp/crl')
	end
end
