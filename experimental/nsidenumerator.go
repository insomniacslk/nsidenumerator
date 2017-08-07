package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/insomniacslk/dns"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
)

// TODO implement timeout

func removeDuplicates(elements []string) []string {
	elemap := make(map[string]bool)
	var ret []string
	for _, element := range elements {
		if _, ok := elemap[element]; !ok {
			elemap[element] = true
			ret = append(ret, element)
		}
	}
	return ret
}

func extractNSIDs(msg *dns.Msg) ([]string, error) {
	var nsids []string
	if len(msg.Extra) > 0 {
		for i := 0; i < len(msg.Extra); i++ {
			rr := msg.Extra[i]
			if rr != nil && rr.Header().Rrtype == dns.TypeOPT {
				opt := (rr).(*dns.OPT)
				for _, s := range opt.Option {
					switch e := s.(type) {
					case *dns.EDNS0_NSID:
						nsid, err := hex.DecodeString(e.Nsid)
						if err != nil {
							return nil, err
						}
						nsids = append(nsids, string(nsid))
					}
				}
			}
		}
	}
	return nsids, nil
}

func resolve(target *string) (*string, error) {
	if i := net.ParseIP(*target); i != nil {
		return target, nil
	}
	log.Printf("Target is not an IP. Trying to resolve it: %s", *target)
	ips, err := net.LookupHost(*target)
	if err != nil {
		return nil, err
	}
	if len(ips) > 1 {
		log.Printf("More than one IP associated to %s, using the first one", *target)
	}
	return &ips[0], nil
}

type ProbeResult struct {
	Nsids []string
	Err   error
}

func sendProbe(client *dns.Client, qname string, qtype, qclass uint16, target string, sourcePort, destPort uint16) ([]string, error) {
	remoteAddr := net.JoinHostPort(target, strconv.Itoa(int(destPort)))
	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
			Opcode:           dns.OpcodeQuery,
		},
		Question: make([]dns.Question, 1),
	}
	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
	}
	ext := &dns.EDNS0_NSID{
		Code: dns.EDNS0NSID,
	}
	opt.Option = append(opt.Option, ext)
	opt.SetUDPSize(dns.DefaultMsgSize)
	msg.Extra = append(msg.Extra, opt)
	msg.Question[0] = dns.Question{Name: dns.Fqdn(qname), Qtype: qtype, Qclass: qclass}
	resp, _, err := client.Exchange(msg, remoteAddr, fmt.Sprintf(":%d", sourcePort))
	if err != nil {
		log.Fatalf("DNS query failed: %v", err)
	}
	nsids, err := extractNSIDs(resp)
	if err != nil {
		return nil, err
	}
	return nsids, nil
}

var resolver = flag.String("resolver", "", "The target DNS IP or hostname to send the queries to")
var qname = flag.String("qname", ".", "The DNS name to query for")
var qtype_s = flag.String("qtype", "A", "The DNS query type to use")
var qtype uint16
var qclass_s = flag.String("qclass", "IN", "The DNS query class to use")
var qclass uint16
var timeout_i = flag.Int("timeout", 1, "The time to wait for a DNS response")
var timeout uint16
var sport_i = flag.Int("sport", 12345, "The base source port to use for the probes")
var sport uint16
var dport_i = flag.Int("dport", 53, "The destination port to use for the probes")
var dport uint16
var paths_i = flag.Int("paths", 1, "The number of paths to enumerate")
var paths uint8
var id_server = flag.Bool("id_server", false,
	"Use this preset to run a CHAOS TXT id.server. query with NSID")

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
	if *id_server {
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
	timeout = uint16(*timeout_i)
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
}

func ProbeServers(qname string, qtype, qclass uint16, resolver_ip string, baseSourcePort, destPort uint16, paths uint8) ([]string, error) {
	client := new(dns.Client)
	client.Net = "udp"
	var wg sync.WaitGroup
	wg.Add(int(paths))
	results := make(chan []string)
	var sourcePort uint16
	for sourcePort = baseSourcePort; sourcePort < baseSourcePort+uint16(paths); sourcePort++ {
		go func(sourcePort uint16) {
			defer wg.Done()
			nsids, err := sendProbe(client, qname, qtype, qclass, resolver_ip, sourcePort, destPort)
			if err != nil {
				log.Print(err)
				return
			}
			results <- nsids
		}(sourcePort)
	}

	var servers []string
	go func() {
		wg.Wait()
		close(results)
	}()

	for nsids := range results {
		servers = append(servers, nsids...)
	}

	return removeDuplicates(servers), nil
}

func main() {
	initArgs()

	resolver_ip, err := resolve(resolver)
	if err != nil {
		log.Fatalf("%v", err)
	}

	plural := ""
	if paths > 1 {
		plural = "s"
	}
	if !*quiet {
		log.Printf("Enumerating %d path%s on %s(%s):%d with base source port %d and timeout %ds",
			paths, plural, *resolver, *resolver_ip, dport, sport, timeout)
	}

	servers, err := ProbeServers(*qname, qtype, qclass, *resolver, sport, dport, paths)
	if err != nil {
		panic(err)
	}
	for idx, nsid := range servers {
		if *quiet {
			fmt.Println(nsid)
		} else {
			fmt.Printf("%d) %v\n", idx+1, nsid)
		}
	}
}
