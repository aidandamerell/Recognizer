#!/usr/bin/env ruby
# Written by Aidan Damerell
# 2017

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
require 'resolv'
require './functions'

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
	attr_accessor :http, :http_status, :http_recog
	attr_accessor :ssh, :ssh_status, :ssh_recog, :ssh_recog_status, :ssh_recognise
	attr_accessor :smb, :smb_status, :smb_recog, :smb_recog_status, :smb_recognise

	def initialize(ip, os, name, ssh, smb, http, type, status)
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
	end

	def os_ident
		if self.smb_recog.nil?
			if self.ssh_recog.nil?
				self.os = self.http_recog
			else
				self.os = self.ssh_recog
			end
		else
			self.os = self.smb_recog
		end
	end

	def ssh_recognise
		if self.ssh.nil?
			self.ssh_recog_status = 0
			return
		end
		match = self.ssh.chomp.sub /SSH-\d+\.\d-/, ''
		recog = Recog::Nizer.match('ssh.banner', "#{match}" )
		if recog.nil? or recog.fetch("matched") == "OpenSSH with just a version, no comment by vendor"
			self.ssh_recog_status = 0
			return
		else
		self.ssh_recog = recog.fetch("os.vendor") rescue nil
		self.ssh_recog_status = 1
		end
	end

	def smb_recognise
		if self.smb.nil?
			self.smb_recog_status = 0
			return
		end
		recog = Recog::Nizer.match('smb.native_os', self.smb)
		if recog.nil?
			self.smb_recog_status = 0
			return
		else
			self.smb_recog = recog.fetch("os.product") rescue self.smb_recog = recog.fetch("os.family")
			self.smb_recog_status = 1
		end
	end

	def http_recognise
	if self.http.nil?
		return
	end
	recog = Recog::Nizer.match('http_header.server', self.http)
	if recog.nil?
	elsif recog.has_key?("os.product")
		self.http_recog = recog.fetch("os.product")
	else
		self.http_recog = recog.fetch("service.vendor")
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
	opt :timeout, "SMB Timeout", :type => :float, :default => 0.8
	opt :verbose, "Verbose output"
	opt :tenpercent, "Used for ITHC, calculates the number of hosts", :type => :integer
	opt :search, "Search for a particular OS type from the collected information", :type => :string
	opt :csv, "Output data to CSV", :type => :string, :default => "recognizer"
	opt :restore, "Restore from an existing output", :type => :string
	opt :nodns, "Do not perform DNS resolution"
end

begin
	if opts[:hosts]
		puts "Read hosts file...\n\n"
		init_read = File.readlines(opts[:hosts])
		init_read.each do |line|
			enumerate << NetAddr::CIDR.create(line.chomp).enumerate
		end
		enumerate.flatten!
		enumerate.each do |ip|
			hosts << Host.new(ip,nil,nil,nil,nil,nil,nil,nil)
		end
	elsif opts[:network]
		puts "Enumerating address space...\n\n"
		enumerate = NetAddr::CIDR.create(opts[:network]).enumerate
		enumerate.each do |ip|
			hosts << Host.new(ip,nil,nil,nil,nil,nil,nil,nil)
		end
	elsif opts[:restore]
		puts "Parsing hosts YAML file...\n\n"
		hosts = YAML.load_file(opts[:restore])
	end
rescue NetAddr::ValidationError
	puts "Invalid IP address".red
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
		smb_connect(host,opts[:timeout])
		ssh_connect(host, opts[:timeout])
		http_connect(host, opts[:timeout])
		host.smb_recognise
		host.ssh_recognise
		host.http_recognise
		device_type(host, types)
		host.os_ident
		unless opts[:nodns]
			resolver(host)
		end
		if opts[:verbose]
			if host.ssh_status == 'live' or host.smb_status == 'live' or host.http_status == 'live'
				if host.os == nil
					puts info.light_blue + " #{host.ip} : #{host.name} => unknown"
				else
					puts good.green + " #{host.ip} : #{host.name} => #{host.os}"
				end
			else
				puts bad.red + " #{host.ip}"
			end
		else
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
	csv << ["IP","Name", "TYPE", "OS","SSH string", "SMB string", "HTTP String"]
		ten_percent.each do |host|
			csv << [host.ip, host.name, host.type, host.os, host.ssh, host.smb, host.http]
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
	csv << ["IP","Name","OS","SSH string", "SMB String", "HTTP String"]
	hosts.each do |host|
		csv << [host.ip, host.name, host.os, host.ssh, host.smb, host.http]
	end
end