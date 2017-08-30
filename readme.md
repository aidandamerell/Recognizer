# RECOGNIZER

## Synopsis

This script can be used to map a corporate network, using SMB and SSH to connect to hosts. This information is then parsed and compared to existing signatures to fingerprint the OS marking it as either a workstation, windows server, linux server or infrastructure device.
This can be very useful on an internal penetration test when a limited scope is provided.

A representative sample feature is also available. This feature was built for ITHC jobs which can require a 10% sample scan of an estate. It's all well and good scanning 10% of the Windows 10 hosts and missing the one Windows XP host.

Tested on Mac OS and Kali Linux.

## Options
```
  -h, --hosts=          Host file
  -n, --network=        CIDR address
  -t, --threads=        Number of threads to run (default: 5)
  -i, --timeout=        SMB Timeout (default: 0.6)
  -v, --verbose           Verbose output
  -e, --tenpercent=     Used for ITHC, calculates the number of hosts
  -s, --search            Search for a particular OS type from the collected information
  -c, --csv=            Output data to CSV (default: recognizer)
  -r, --restore=        Restore from an existing output
  -l, --help              Show this message
```

## Motivation

This script is aimed at simplifying the identification of hosts on a network as internal penetration test are usually scoped with just a IP range, this can involve a large amount of messing around trying to identify each host and its type.

## Installation

Gem file included.
```
$ bundle install
```
## Example
Standard scan against single a /29 with verbose output on:
```
$ recognizer.rb -n 10.129.121.240/29 -v
[-] 10.129.121.243                            
[-] 10.129.121.244
[+] 10.129.121.240 = Windows Server 2008
[+] 10.129.121.242 = Windows Server 2003 R2 (SP)
[-] 10.129.121.245                           
[+] 10.129.121.241 = Windows Server 2008
[+] 10.129.121.246 = Windows Server 2003 (SP)
[-] 10.129.121.247
```
The script will output multiple files dependant on flags set.
Unless restoring a session, the connection_data.yaml fill will be produced, this contains the data on a per host basis and can be used to restore for further parsing.
Output is to a CSV file.



### Contributors

Thanks to Owen Bellis for the idea.
