package main

import (
	nsidenumerator "../lib"
	"errors"
	"flag"
	"fmt"
	// pending https://github.com/miekg/dns/pull/502
	"github.com/insomniacslk/dns"
	"log"
	"net"
	"strings"
	"time"
)

func resolve(address *string, ip_version int) (*net.IP, error) {
	if ip_version != 0 && ip_version != 4 && ip_version != 6 {
		return nil, errors.New(fmt.Sprintf("Invalid IP version: %v", ip_version))
	}
	if ip := net.ParseIP(*address); ip != nil {
		if ip_version == 0 {
			return &ip, nil
		}
		if ip_version == 4 && ip.To4() == nil {
			return nil, errors.New(fmt.Sprintf("Invalid IPv4: %v", ip))
		}
		if ip_version == 6 && ip.To4() != nil {
			return nil, errors.New(fmt.Sprintf("Invalid IPv6: %v", ip))
		}
	}
	ips, err := net.LookupHost(*address)
	if err != nil {
		return nil, err
	}
	for _, ip_s := range ips {
		ip := net.ParseIP(ip_s)
		if ip == nil {
			return nil, errors.New(fmt.Sprintf("Invalid IP: %v", ip))
		}
		if ip_version == 0 {
			return &ip, nil
		}
		if ip_version == 4 && ip.To4() != nil {
			return &ip, nil
		}
		if ip_version == 6 && ip.To4() == nil {
			return &ip, nil
		}
	}
	// if we are here, no suitable IP was found, let's return an error
	var v string
	if ip_version == 0 {
		v = ""
	} else {
		v = fmt.Sprintf("v%d", ip_version)
	}
	return nil, errors.New(fmt.Sprintf("No valid IP%v found for %v", v, *address))
}

var resolver = flag.String("resolver", "", "The target DNS IP or hostname to send the queries to")
var qname = flag.String("qname", ".", "The DNS name to query for")
var qtype_s = flag.String("qtype", "A", "The DNS query type to use")
var qtype uint16
var qclass_s = flag.String("qclass", "IN", "The DNS query class to use")
var qclass uint16
var timeout_i = flag.Int("timeout", 1000, "The milliseconds to wait for a DNS response")
var timeout time.Duration
var sport_i = flag.Int("sport", 12345, "The base source port to use for the probes")
var sport uint16
var dport_i = flag.Int("dport", 53, "The destination port to use for the probes")
var dport uint16
var paths_i = flag.Int("paths", 1, "The number of paths to enumerate")
var paths uint8
var id_server = flag.Bool("id_server", false,
	"Use this preset to run a CHAOS TXT id.server. query with NSID")
var v4 = flag.Bool("4", false, "Force IPv4")
var v6 = flag.Bool("6", false, "Force IPv6")

//var verbose = flag.Bool("verbose", false, "Print verbose output")
var quiet = flag.Bool("quiet", false, "Print minimal information")

func initArgs() {
	flag.Parse()
	if *resolver == "" {
		log.Fatalf("Error: resolver cannot be empty")
	}
	/*
		if *verbose && *quiet {
			log.Fatal("Cannot use --verbose and --quiet together")
		}
	*/
	if *id_server && !*quiet {
		log.Printf("Warning: using --id-server overrides --qname, --qclass and --qtype")
		*qname = "id.server."
		*qtype_s = "TXT"
		*qclass_s = "CH"
	}
	qt, ok := dns.StringToType[strings.ToUpper(*qtype_s)]
	if !ok {
		log.Fatalf("Invalid query type: %v", *qtype_s)
	}
	qtype = qt
	qc, ok := dns.StringToClass[strings.ToUpper(*qclass_s)]
	if !ok {
		log.Fatalf("Invalid query class: %v", *qclass_s)
	}
	qclass = qc
	if *timeout_i < 1 || *timeout_i > 0xffff {
		log.Fatalf("Timeout must be a number between 1 and 65535")
	}
	timeout = time.Duration(*timeout_i * 1000000)
	if *sport_i < 1 || *sport_i > 0xffff {
		log.Fatalf("Source port must be a number between 1 and 65535")
	}
	sport = uint16(*sport_i)
	if *dport_i < 1 || *dport_i > 0xffff {
		log.Fatalf("Destination port must be a number between 1 and 65535")
	}
	dport = uint16(*dport_i)
	if *paths_i < 1 || *paths_i > 0xff {
		log.Fatalf("Paths must be a number between 1 and 255")
	}
	paths = uint8(*paths_i)
	if uint32(sport)+uint32(paths) > 0xffff {
		log.Fatalf("Source port + paths must be <= 65535")
	}
	if *v4 && *v6 {
		log.Fatalf("Cannof force both IPv4 and IPv6")
	}
}

func main() {
	initArgs()

	ipVersion := 0
	if *v6 {
		ipVersion = 6
	} else if *v4 {
		ipVersion = 4
	}

	nsid := nsidenumerator.NSIDEnumerator{
		Qname:          *qname,
		Qtype:          qtype,
		Qclass:         qclass,
		Resolver:       *resolver,
		IpVersion:      ipVersion,
		BaseSourcePort: sport,
		DestPort:       dport,
		Paths:          paths,
		Timeout:        timeout,
	}

	plural := ""
	if paths > 1 {
		plural = "s"
	}
	if !*quiet {
		log.Printf("Enumerating %d path%s on %s:%d with base source port %d and timeout %v",
			nsid.Paths, plural, nsid.Resolver, nsid.DestPort, nsid.BaseSourcePort, nsid.Timeout)
	}

	results, err := nsid.Enumerate()
	if err != nil {
		log.Fatal(err)
	}

	for idx, nsid := range results {
		if *quiet {
			fmt.Println(nsid)
		} else {
			fmt.Printf("%d) %v\n", idx+1, nsid)
		}
	}
}
