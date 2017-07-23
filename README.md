# NSID enumerator: show DNS servers behind anycast IPs using NSID

As simple as that: run DNS queries towards an anycast-enabled, NSID-enabled DNS server
(e.g. the root servers) to know what the backend servers are. Leverage ECMP
(Equal-Cost MultiPath) for the enumeration.

This tool uses NSID to get the backend server name, which is in-band in any regular DNS
query. See `--id-server` if you want to also run a CHAOS/TXT `id.server.` query.

## Dependencies

* Python 3
* dnspython

## Example:

### Enumeration

Enumerate the backend servers behind `k.root-servers.net.` using 10 paths:
```
$ ./nsidenumerator.py k.root-servers.net -e 10
Enumerating 10 paths
Found 3 servers
b'ns1.gb-lon.k.ripe.net'
b'ns2.gb-lon.k.ripe.net'
b'ns3.gb-lon.k.ripe.net'

## Statistics
Total DNS queries      : 10
Timeouts               : 0
Percent failed queries : 0.00

## Warnings
    none
```

### Single query

One query (hence one path and one backend server), source port 12345, verbose mode:

```
$ ./nsidenumerator.py k.root-servers.net -v
DNS query to k.root-servers.net(193.0.14.129). Qname: '.', qtype: A, qclass: IN, sport: 12345, dport: 53, timeout 1.0
Found 1 servers
b'ns2.gb-lon.k.ripe.net'

## Statistics
Total DNS queries      : 1
Timeouts               : 0
Percent failed queries : 0.00

## Warnings
    none
```

## Usage

```
$ ./nsidenumerator.py --help
usage: nsidenumerator.py [-h] [-n QNAME] [-t QTYPE] [-c {IN,CH}] [-T TIMEOUT]
                         [-s SPORT] [-d DPORT] [-e ENUMERATE] [-I] [-v] [-q]
                         target

positional arguments:
  target                The target DNS server.

optional arguments:
  -h, --help            show this help message and exit
  -n QNAME, --qname QNAME
                        The DNS name to query for. Default: '.'
  -t QTYPE, --qtype QTYPE
                        Query type to use. Default: A
  -c {IN,CH}, --qclass {IN,CH}
                        Query class to use. Default: IN
  -T TIMEOUT, --timeout TIMEOUT
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
  -I, --id-server       Run a CHAOS TXT id.server. query along with NSID, and
                        match the answers
  -v, --verbose         Print verbose output. Default: False
  -q, --quiet           Print the minimum necessary information. Default:
                        False
```
