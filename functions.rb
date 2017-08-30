def smb_connect(host, timeout)
	output = ''
	cmd = TTY::Command.new(output: output)
	connection = cmd.run!("smbclient -g --no-pass -L", host.ip, timeout: timeout)
	result = connection.err.lines.first
	if result.nil?
		host.smb_status = "timeout"
	else
		host.smb = result [/(?<=OS=\[)(.*?)(?=\])/]
		host.smb_status = "live"
	end
end

def ssh_connect(host, timeout)
	begin 
	    Timeout.timeout(timeout) do
	        connection = TCPSocket.new "#{host.ip}", 22
	        host.ssh = connection.first.chomp
	        host.ssh_status = 'live'
	    end
	rescue Timeout::Error
		host.ssh_status = "timeout"
	rescue Errno::ECONNREFUSED, Errno::EACCES, Errno::EHOSTUNREACH, Errno::EHOSTDOWN, Errno::ENETUNREACH, Errno::ECONNRESET => error
		host.ssh_status = error.class.to_s
	rescue
		
	end
end


def device_type(host, types)
	if host.smb_recog.nil?
		if host.ssh_recog.nil?
			recog = host.http_recog
		else
			recog = host.ssh_recog
		end
	else
		recog = host.smb_recog
	end
	types.each do |system|
		if recog == system.name
			system.counter += 1
			host.type = system.type
			system.ip << host
		end
	end
end

def http_connect(host, timeout)
	response = nil
	Net::HTTP.start(host.ip, 80, :read_timeout => timeout, :continue_timeout => timeout, :open_timeout => timeout) {|http|
	  response = http.head('/')
	}
	host.http = response['Server']
	host.http_status = 'live'
rescue Errno::ECONNRESET, Net::ReadTimeout, Errno::ETIMEDOUT, Net::OpenTimeout, Errno::ECONNREFUSED, Errno::EACCES, Errno::EHOSTUNREACH, Errno::EHOSTDOWN, Errno::ENETUNREACH, OpenSSL::SSL::SSLError => error
	host.http_status = error.class.to_s
end

#Function to calculate 10% of identified hosts
def ten_percent(hosts, types, required, ten_percent)
	nolt = 0
	total_count = 0
	not_empty = []
	required = (required*1.1)
	types.each do |type|
		total_count += type.counter
		unless type.ip.empty?
			nolt += 1
			not_empty << type
		end
	end
	if total_count <= required
		puts "Not enough hosts...".red
		exit
	end
	per_type = (required/nolt.to_f).ceil
	not_empty.each do |type|
		 ten_percent << type.ip.sample(per_type)
		 if type.ip.sample(per_type).count < per_type
		 	per_type += per_type + (per_type - type.ip.sample(per_type).count)
		 end
	end
	ten_percent.flatten!
end

def resolver(host)
	host.name = Resolv.getname "#{host.ip}"
rescue Resolv::ResolvError
	host.name = "No DNS Name"
end
