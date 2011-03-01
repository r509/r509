#!/usr/bin/ruby

require 'rubygems'
require 'r509'
require 'openssl'

csr = R509::Csr.new
subject = OpenSSL::X509::Name.new
if ARGV[0].nil? then
	puts "Interactive CSR generation using r509."
	puts "You can also call with 1 or 2 args (string subject, int bit_strength)"
	subject = []
	print "C (US): "
	c = gets.chomp
	c = c.empty? ? 'US':c;
	subject.push ['C',c]

	print "ST (Illinois): "
	st = gets.chomp
	st = st.empty? ? 'Illinois':st;
	subject.push ['ST',st]

	print "L (Chicago): "
	l = gets.chomp
	l = l.empty? ? 'Chicago':l;
	subject.push ['L',l]
	
	print "O (r509 LLC): "
	o = gets.chomp
	o = o.empty? ? 'r509 LLC':o;
	subject.push ['O',o]

	print "CN: "
	subject.push ['CN',gets.chomp]
	print "SAN Domains (comma separated):"
	san_domains = []
	san_domains = gets.chomp.split(',').collect { |domain| domain.strip }
	csr.create_with_subject subject,2048,san_domains
else
	ARGV[0].split('/').each { |item|
		if item != '' then
			value = item.split('=')
			subject.add_entry(value[0],value[1])
		end
	}
	bit_strength = nil
	if ARGV.size > 1 then
		bit_strength = ARGV[1].to_i
	else
		bit_strength = 2048
	end
	csr.create_with_subject subject,bit_strength
end
puts csr.key
puts csr
puts csr.subject
if RUBY_PLATFORM.match('darwin') != nil then
	IO.popen('pbcopy','w').puts csr
end
