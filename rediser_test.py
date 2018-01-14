#!/usr/bin/env python

import argparse
from rediser import tprint, Client, ClusterClient

def test_client(host='127.0.0.1', port=1279):
    cases = [
        [('set', 'hello', 'world'), 'OK'],
        [('get', 'hello'), 'world'],
    ]
    tprint('---------------test client----------------')
    c = Client(host=host, port=port)
    for case in cases:
        r = c.call(*case[0])
        if r == case[1]:
            tprint('PASS', '%s:%s' % (repr(case[0]), repr(r)))
        else:
            tprint('FAIL', '%s:%s != %s' % (repr(case[0]), repr(r), repr(case[1])))

def test_cluster_client(addrs=['192.168.2.107:2211']):
    cases = [
        [('set', 'hello', 'world'), 'OK'],
        [('get', 'hello'), 'world'],
    ]
    tprint('---------------test cluster client----------------')
    c = ClusterClient(addrs)
    for case in cases:
        r = c.call(*case[0])
        if r == case[1]:
            tprint('PASS', '%s:%s' % (repr(case[0]), repr(r)))
        else:
            tprint('FAIL', '%s:%s != %s' % (repr(case[0]), repr(r), repr(case[1])))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('cmd', nargs='?', choices=['all', 'client', 'clusterclient'], default='all', help='specify test command')
    args = parser.parse_args()
    if args.cmd == 'client':
        test_client()
    elif args.cmd == 'clusterclient':
        test_cluster_client()
    elif args.cmd == 'all':
        test_client()
        test_cluster_client()

