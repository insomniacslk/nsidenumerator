package nsidenumerator

import (
	"encoding/hex"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"net"
	"strconv"
	"time"
)

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

type Probe struct {
	Client     *dns.Client
	Qname      string
	Qtype      uint16
	Qclass     uint16
	Resolver   string
	SourcePort uint16
	DestPort   uint16
	Timeout    time.Duration
}

func (p *Probe) String() string {
	return fmt.Sprintf(
		"Probe(qname='%v', qtype='%v', qclass='%v', resolver='%v', sourcePort=%v, destPort=%v)",
		p.Qname, dns.TypeToString[p.Qtype], dns.ClassToString[p.Qclass], p.Resolver, p.SourcePort, p.DestPort,
	)
}

func (p *Probe) Send() ([]string, error) {
	remoteAddr := net.JoinHostPort(p.Resolver, strconv.Itoa(int(p.DestPort)))
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
	msg.Question[0] = dns.Question{Name: dns.Fqdn(p.Qname), Qtype: p.Qtype, Qclass: p.Qclass}
	laddr := net.UDPAddr{IP: nil, Port: int(p.SourcePort), Zone: ""}
	p.Client = new(dns.Client)
	p.Client.Dialer = &net.Dialer{
		Timeout:   p.Timeout,
		LocalAddr: &laddr,
	}
	resp, _, err := p.Client.Exchange(msg, remoteAddr)
	if err != nil {
		log.Fatalf("DNS query failed: %v", err)
	}
	nsids, err := extractNSIDs(resp)
	if err != nil {
		return nil, err
	}
	return nsids, nil
}
