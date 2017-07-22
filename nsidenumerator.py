#!/usr/bin/env python3

'''
Enumerate DNS servers behind anycast VIPs using the NSID EDNS extension
(RFC 5001)
'''

import argparse
import ipaddress

import dns.query
import dns.message
import dns.resolver
import dns.rdatatype
import dns.rdataclass


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'target', help='The target DNS server.')
    parser.add_argument(
        '-q', '--qname', default='.',
        help='The DNS name to query for. Default: %(default)r')
    parser.add_argument(
        '-t', '--timeout', type=float, default=1.,
        help='Timeout before the DNS request expires')
    parser.add_argument('-s', '--sport', type=int, default=12345,
        help='The UDP source port to use for the query. '
        'Default: %(default)s')
    parser.add_argument('-d', '--dport', type=int, default=53,
        help='The UDP destination port to use for the query. '
        'Default: %(default)s')
    parser.add_argument('-e', '--enumerate', type=int,
        help='Enumerate DNS servers using the specified number of paths. '
        'Default: %(default)s')
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
        help='Print verbose output')
    return parser.parse_args()


def resolve(name, qtype='A'):
    # return the first one, if any. If you want more control, use explicit IPs
    for ans in dns.resolver.query(name, qtype).response.answer:
        return ans.items[0].to_text()
    return ''


def main():
    args = parse_args()
    try:
        ipaddress.ip_address(args.target)
    except ValueError:
        target = resolve(args.target)
    q = dns.message.make_query(args.qname, dns.rdatatype.A, dns.rdataclass.IN)
    q.use_edns(payload=4096, options=[dns.edns.GenericOption(dns.edns.NSID, b'')])

    start_sport = args.sport
    if args.enumerate is not None:
        print('Enumerating {} paths'.format(args.enumerate))
        end_sport = start_sport + args.enumerate
    else:
        end_sport = start_sport

    servers = set()
    for sport in range(start_sport, end_sport + 1):
        if args.verbose:
            print('DNS query to {}({}). Qname: {!r}, sport: {}, dport: {}, timeout {}'.format(
            args.target, target, args.qname, sport, args.dport, args.timeout))
        ans = dns.query.udp(q, target, timeout=args.timeout,
                source_port=sport, port=args.dport)
        for opt in ans.options:
            if opt.otype == dns.edns.NSID:
                servers.add(opt.data)

    print('Found {} servers:'.format(len(servers)))
    for server in sorted(servers):
        print(server)


if __name__ == '__main__':
    main()
