package nsidenumerator

import (
	"github.com/insomniacslk/dns"
	"log"
	"sort"
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

type NSIDEnumerator struct {
	Qname          string
	Qtype          uint16
	Qclass         uint16
	Resolver       string
	IpVersion      int
	BaseSourcePort uint16
	DestPort       uint16
	Paths          uint8
	Timeout        time.Duration
}

func (n *NSIDEnumerator) Enumerate() ([]string, error) {
	// start probing
	var wg sync.WaitGroup
	wg.Add(int(n.Paths))
	results := make(chan []string)
	net := "udp"
	if n.IpVersion == 4 {
		net = "udp4"
	} else if n.IpVersion == 6 {
		net = "udp6"
	}
	var sourcePort uint16
	for sourcePort = n.BaseSourcePort; sourcePort < n.BaseSourcePort+uint16(n.Paths); sourcePort++ {
		go func(sourcePort uint16) {
			defer wg.Done()
			client := new(dns.Client)
			client.Net = net
			probe := Probe{Client: client, Qname: n.Qname, Qtype: n.Qtype, Qclass: n.Qclass, Resolver: n.Resolver, SourcePort: sourcePort, DestPort: n.DestPort, Timeout: n.Timeout}
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
	sort.Strings(servers)
	servers = removeDuplicates(servers)
	return servers, nil
}
