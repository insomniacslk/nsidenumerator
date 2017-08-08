package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"github.com/insomniacslk/dns"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

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
	return nil, errors.New(fmt.Sprintf("No valid IP found for %v", address))
}

type Probe struct {
	client     *dns.Client
	qname      string
	qtype      uint16
	qclass     uint16
	resolver   string
	sourcePort uint16
	destPort   uint16
}

func (p *Probe) String() string {
	return fmt.Sprintf(
		"Probe(qname='%v', qtype='%v', qclass='%v', resolver=%v, sourcePort=%v, destPort=%v)",
		p.qname, dns.TypeToString[p.qtype], dns.ClassToString[p.qclass], p.resolver, p.sourcePort, p.destPort,
	)
}

func (p *Probe) Send() ([]string, error) {
	remoteAddr := net.JoinHostPort(p.resolver, strconv.Itoa(int(p.destPort)))
	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
			Opcode:           dns.OpcodeQuery,
		},
		Question: make([]dns.Question, 1),
	}
	p.client.LocalAddr = &net.UDPAddr{IP: nil, Port: int(p.sourcePort), Zone: ""}
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
	msg.Question[0] = dns.Question{Name: dns.Fqdn(p.qname), Qtype: p.qtype, Qclass: p.qclass}
	var ctx context.Context
	ctx, _ = context.WithTimeout(context.Background(), timeout)
	resp, _, err := p.client.ExchangeContext(ctx, msg, remoteAddr)
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

func ProbeServers(qname string, qtype, qclass uint16, resolver_ip net.IP, baseSourcePort, destPort uint16, paths uint8, timeout time.Duration) ([]string, error) {
	var wg sync.WaitGroup
	wg.Add(int(paths))
	results := make(chan []string)
	net := "udp"
	if resolver_ip.To4() != nil {
		net = "udp4"
	} else {
		net = "udp6"
	}
	var sourcePort uint16
	for sourcePort = baseSourcePort; sourcePort < baseSourcePort+uint16(paths); sourcePort++ {
		go func(sourcePort uint16) {
			defer wg.Done()
			client := new(dns.Client)
			client.Net = net
			probe := Probe{client: client, qname: qname, qtype: qtype, qclass: qclass, resolver: *resolver, sourcePort: sourcePort, destPort: destPort}
			nsids, err := probe.Send()
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

	ip_version := 0
	if *v6 {
		ip_version = 6
	} else if *v4 {
		ip_version = 4
	}
	resolver_ip, err := resolve(resolver, ip_version)
	if err != nil {
		log.Fatalf("%v", err)
	}

	plural := ""
	if paths > 1 {
		plural = "s"
	}
	if !*quiet {
		log.Printf("Enumerating %d path%s on %s(%s):%d with base source port %d and timeout %v",
			paths, plural, *resolver, *resolver_ip, dport, sport, timeout)
	}

	servers, err := ProbeServers(*qname, qtype, qclass, *resolver_ip, sport, dport, paths, timeout)
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
