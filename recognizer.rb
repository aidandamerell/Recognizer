#!/usr/bin/env ruby
# Written by Aidan Damerell
# 2017

#Need to build in http body recoginition

require 'trollop'
require 'colorize'
require 'tty-command'
require 'netaddr'
require 'threadify'
require 'fileutils'
require 'ruby-progressbar'
require 'recog'
require 'timeout'
require 'socket'
require 'csv'
require 'yaml'
require 'net/http'
require 'net/ftp'
require 'resolv'
require_relative './functions'
require 'pp'
require 'nmap/xml'

Signal.trap("INT") { 
  shut_down 
  exit
}

def shut_down
  puts "\nShutting down...".light_blue
  exit
end

system 'clear'
banner = 
'
______                           _              
| ___ \                         (_)              _           _
| |_/ /___  ___ ___   __ _ _ __  _ _______ _ __ \ [===[*]===] /   
|    // _ \/ __/ _ \ / _` | `_ \| |_  / _ \ `__| ||         || 
| |\ \  __/ (_| (_) | (_| | | | | |/ /  __/ |    ||         ||
\_| \_\___|\___\___/ \__, |_| |_|_/___\___|_|    \\\         //
 V1.1                 __/ |              
                     |___/                                   

'
puts banner.green

class Type
	attr_accessor :name, :counter, :ip, :type
	def initialize(name, count, ip)
		@name = name
		@type = type
		@counter = counter
		@ip = ip
	end
end

class Host

	attr_accessor :ip, :os, :name, :type
	attr_accessor :http, :http_status, :http_recog, :https_status
	attr_accessor :ssh, :ssh_status, :ssh_recog, :ssh_recog_status, :ssh_recognise
	attr_accessor :smb, :smb_status, :smb_recog, :smb_recog_status, :smb_recognise
	attr_accessor :ftp, :ftp_status, :ftp_recog

	def initialize(ip, smb_status, ssh_status, ftp_status, http_status)
		@ip = ip
		@os = os
		@name = name
		@type = type

		@smb = smb
		@smb_status = smb_status
		@smb_recog = smb_recog
		@smb_recog_status = smb_recog_status

		@ssh = ssh
		@ssh_recog = ssh_recog
		@ssh_status = ssh_status
		@ssh_recog_status = ssh_recog_status

		@http = http
		@http_status = http_status
		@http_recog = http_recog
		@https_status = https_status

		@ftp = ftp
		@ftp_status = ftp_status
		@ftp_recog = ftp_recog
	end

	def os_ident
		if self.smb_recog.nil?
			if self.ssh_recog.nil?
				if self.http_recog.nil?
					self.os = self.ftp_recog
				else
					self.os = self.http_recog
				end
			else
				self.os = self.ssh_recog
			end
		else
			self.os = self.smb_recog
		end
	end

	def self.ssh_recognise(host)
		if host.ssh.nil?
			host.ssh_recog_status = 0
			return
		end
		match = host.ssh.chomp.sub /SSH-\d+\.\d-/, ''
		recog = Recog::Nizer.match('ssh.banner', "#{match}")
		if recog.nil? or recog.fetch("matched") == "OpenSSH with just a version, no comment by vendor"
			host.ssh_recog_status = 0
			return
		else
		host.ssh_recog = recog.fetch("os.vendor") rescue nil
		host.ssh_recog_status = 1
		end
	end

	def self.smb_recognise(host)
		if host.smb.nil?
			host.smb_recog_status = 0
			return
		end
		recog = Recog::Nizer.match('smb.native_os', host.smb)
		if recog.nil?
			host.smb_recog_status = 0
			return
		else
			host.smb_recog = recog.fetch("os.product") rescue host.smb_recog = recog.fetch("os.family")
			host.smb_recog_status = 1
		end
	end
#quick fix need to sort
	def self.http_recognise(host)
		if host.http.nil?
			return
		end
		recog = Recog::Nizer.match('http_header.server', host.http)
		if recog.nil? or recog["matched"] =~ /nginx|no version information/
		elsif recog.has_key?("apache.info")
			host.http_recog = recog.fetch("apache.info").scan(/(?<=\()(.*?)(?=\))/).first.reduce
		elsif recog.has_key?("os.product")
			host.http_recog = recog.fetch("os.product")
		elsif recog.has_key?("os.product")
			host.http_recog = recog.fetch("os.product")
		else
			host.http_recog = recog.fetch("service.vendor")
		end
	end

	def self.ftp_recognise(host)
		recog = Recog::Nizer.match('ftp.banner', host.ftp)
		if recog.nil?
		elsif recog.has_key?("os.product")
			host.ftp_recog = recog.fetch("os.product")
		elsif recog.has_key?("service.product")
			host.htftp_recog = recog.fetch("service.product")
		else
			host.ftp_recog = recog.fetch("service.vendor")
		end
	end

  #Need to find some more
	def self.http_page_recog(host,page)
		if page =~ /ID_EESX_Welcome/
			host.http == "ESXI"
		elsif page =~ /WordPress site/
			host.http = "SOMETHING ELSE"
		end
	end

	def statuses
		#Well this was a learning experience
		{
			:ftp => self.ftp_status,
			:ssh => self.ssh_status,
			:smb => self.smb_status,
			:http => self.http_status
		}
	end
end

def nmap(file, hosts)
	puts "Parsing nmap XML...".yellow
	Nmap::XML.new(file) do |xml|
		xml.each_host do |host|
			hosts << current = Host.new(host.ip,nil,nil,nil, nil)
			host.each_port do |port|
				if port.number == 22 && port.state.to_s == "open"
					current.ssh_status = "live"
				end
				if port.number == 80 && port.state.to_s == "open"
					current.http_status = "live"
				end
				if port.number == 445 && port.state.to_s == "open"
					current.smb_status = "live"
				end
				if port.number == 21 && port.state.to_s == "open"
					current.ftp_status = "live"
				end
			end
		end
	end
end


types = YAML.load_file("types.yaml")
hosts = []
ten_percent = []
enumerate = []
good = "[+]"
bad = "[-]"
info = "[*]"

opts = Trollop::options do
	opt :hosts, "Host file", :type => :string
	opt :network, "CIDR address", :type => :string
	opt :threads, "Number of threads to run", :type => :integer, :default => 5
	opt :timeout, "SMB Timeout", :type => :float, :default => 1.0
	opt :verbose, "Verbose output"
	opt :tenpercent, "Used for ITHC, calculates the number of hosts", :type => :integer
	opt :search, "Search for a particular OS type from the collected information", :type => :string
	opt :csv, "Output data to CSV", :type => :string, :default => "recognizer"
	opt :restore, "Restore from an existing output", :type => :string
	opt :nodns, "Do not perform DNS resolution"
	opt :nmap, "Nmap parse", :type => :string
end

begin
	if opts[:hosts]
		puts "Read hosts file...\n\n"
		init_read = File.readlines(opts[:hosts])
		init_read.each do |line|
			# puts line
			enumerate << NetAddr::CIDR.create(line.chomp).enumerate
		end
		enumerate.flatten!
		enumerate.each do |ip|
			hosts << Host.new(ip, "live","live","live","live")
		end
	elsif opts[:network]
		puts "Enumerating address space...\n\n"
		enumerate = NetAddr::CIDR.create(opts[:network]).enumerate
		enumerate.each do |ip|
			hosts << Host.new(ip,"live","live","live","live")
		end
	elsif opts[:restore]
		puts "Parsing hosts YAML file...\n\n"
		hosts = YAML.load_file(opts[:restore])
	elsif opts[:nmap]
		nmap(opts[:nmap], hosts)
	end
rescue NetAddr::ValidationError => error
	puts "Invalid IP address: #{error}".red
	exit
end

#Progress bar
if opts[:search] or opts[:restore]

elsif !opts[:verbose]
	progressbar = ProgressBar.create(:title => "Completed", :format => "%t: %c/%C | %p%% |%B|")
	progressbar.total = hosts.count
else
	progressbar = ProgressBar.create( :format => "")
	progressbar.total = hosts.count
end

unless opts[:restore]
	puts "Commencing scan...\n\n"
	puts "#{info}".light_blue + " Threads: #{opts[:threads]}"
	puts "#{info}".light_blue + " IPs: #{hosts.count}\n\n"
	hosts.threadify(opts[:threads]) {|host|
		progressbar.increment
		host.statuses.each do |type, status|
			if status == 'live'
				Methods.public_send("#{type}_connect", host, opts[:timeout])
				Host.public_send("#{type}_recognise", host)
				if host.send("#{type}_status") == "down" && opts[:nmap]
					puts info.light_blue + "Host up in nmap but we didn't manage to connect, try increase the timeout..."
				end
			else
				host.public_send("#{type}_status=", "down")
			end
		end
		device_type(host, types)
		host.os_ident
		host.type
		unless opts[:nodns]
			resolver(host)
		end
		if opts[:verbose]
			status = (host.smb_status == "live" ? " SMB ".green : " SMB ".red) + (host.ssh_status == "live" ? " SSH ".green : " SSH ".red) + (host.http_status == "live" ? " HTTP ".green : " HTTP ".red) + (host.ftp_status == "live" ? " FTP ".green : " FTP ".red)
			if [host.ssh_status, host.smb_status, host.http_status, host.ftp_status].any? { |i| i == "live"}
				if host.os == nil
					puts info.light_blue + " #{host.ip}:"  + status + ": #{host.os}"
				else
					puts good.green + " #{host.ip}:"  + status + ": #{host.os}"
				end
			else
				puts bad.red + " #{host.ip}:"  + status + ": #{host.os}"
			end
		end
	}

	File.write("connection_data.yaml", hosts.to_yaml)
else
	puts "Live hosts: #{hosts.count {|i| i.os != nil}}"
	hosts.each do |host|
		device_type(host, types)
		host.os_ident
	end
end

# output and ten percent
if opts[:tenpercent]
	ten_percent(hosts,types, opts[:tenpercent], ten_percent)
	puts "Required: #{opts[:tenpercent]}"
	puts "Parsed: #{ten_percent.count}"
	CSV.open("ten_percent.csv", "w+") do |csv|
	csv << ["IP","Name", "TYPE", "OS","SSH string", "SMB string", "HTTP String", "FTP String"]
		ten_percent.each do |host|
			csv << [host.ip, host.name, host.type, host.os, host.ssh, host.smb, host.http, host.ftp]
		end
	end
end


if opts[:search]
	hosts.each do |host|
		if host.os =~ /#{opts[:search]}/im
			puts "#{host.ip} - #{host.name} - #{host.os}"
		end
	end
end

CSV.open("#{opts[:csv]}.csv", "w+") do |csv|
	csv << ["IP","Name","OS","SSH string", "SMB String", "HTTP String", "FTP String"]
	hosts.each do |host|
		csv << [host.ip, host.name, host.os, host.ssh, host.smb, host.http, host.ftp]
	end
end