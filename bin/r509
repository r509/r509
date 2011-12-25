#!/usr/bin/ruby
require 'rubygems'
require 'r509'
require 'r509/version'
require 'openssl'

subject = OpenSSL::X509::Name.new
selfsign = 0
if ARGV[0].nil? then
    puts "Interactive CSR generation using r509 v#{R509::VERSION}."
    puts ""
    puts "You can also call with 1-3 args (string subject, int bit_strength, [optional days selfsign length])"
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

    print "OU (null by default): "
    ou = gets.chomp
    if(!ou.empty?) then
        subject.push ['OU',ou]
    end

    print "CN: "
    subject.push ['CN',gets.chomp]
    print "SAN Domains (comma separated):"
    san_domains = []
    san_domains = gets.chomp.split(',').collect { |domain| domain.strip }
    csr = R509::Csr.new(:subject => subject, :bit_strength => 2048, :domains => san_domains)
    print "Self-signed cert duration in days (null disables self-sign):"
    selfsign_input = gets.chomp
    if selfsign_input.to_i > 0
        selfsign = selfsign_input.to_i
    end


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
    if ARGV.size > 2 and ARGV[2].to_i > 0
        selfsign = ARGV[2].to_i
    end
    csr = R509::Csr.new(:subject => subject, :bit_strength => bit_strength)
end

if selfsign > 0
    ca = R509::CertificateAuthority::Signer.new
    cert = ca.selfsign(:csr => csr, :not_after => Time.now.to_i+86400*selfsign)
    puts csr.key.to_pem
    puts cert
    puts cert.subject
else
    puts csr.key.to_pem
    puts csr
    puts csr.subject
end

if RUBY_PLATFORM.match('darwin') != nil then
    if selfsign > 0
        IO.popen('pbcopy','w').puts cert
    else
        IO.popen('pbcopy','w').puts csr
    end
end
