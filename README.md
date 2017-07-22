# NSID enumerator: show DNS servers behind anycast IPs using NSID

As simple as that: run DNS queries towards an anycast-enabled, NSID-enabled DNS server
(e.g. the root servers) to know what the backend servers are. Leverage ECMP
(Equal-Cost MultiPath) for the enumeration.
Requires root privileges to set the custom UDP source port.

## Dependencies

* Python 3
* dnspython

## Example:

### Enumeration

Enumerate the backend servers behind `k.root-servers.net.` using 10 paths:
```
$ sudo ./nsidenumerator.py $(dig +short k.root-servers.net.) -e 10
Enumerating 10 paths
Found 3 servers:
b'ns1.nl-ams.k.ripe.net'
b'ns2.nl-ams.k.ripe.net'
b'ns3.nl-ams.k.ripe.net'
```

### Single query

One query (hence one path and one backend server), source port 12345:

```
$ sudo ./nsidenumerator.py $(dig +short k.root-servers.net.) -v
DNS query to 193.0.14.129. Qname: '.', sport: 12345, dport: 53, timeout 1.0
Found 1 servers:
b'ns2.nl-ams.k.ripe.net'
```

## Usage

```
$ ./nsidenumerator.py --help
usage: nsidenumerator.py [-h] [-q QNAME] [-t TIMEOUT] [-s SPORT] [-d DPORT]
                         [-e ENUMERATE] [-v]
                         target

positional arguments:
  target                The target DNS server. Default: 193.0.14.129

optional arguments:
  -h, --help            show this help message and exit
  -q QNAME, --qname QNAME
                        The DNS name to query for. Default: .
  -t TIMEOUT, --timeout TIMEOUT
                        Timeout before the DNS request expires
  -s SPORT, --sport SPORT
                        The UDP source port to use for the query. Default:
                        12345
  -d DPORT, --dport DPORT
                        The UDP destination port to use for the query.
                        Default: 53
  -e ENUMERATE, --enumerate ENUMERATE
                        Enumerate DNS servers using the specified number of
                        paths. Default: None
  -v, --verbose         Print verbose output
```
