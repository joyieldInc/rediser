#!/usr/bin/env python

#
# rediser - A redis admin tool.
# Copyright (C) 2017 Joyield, Inc. <joyield.com@gmail.com>
# All rights reserved.
#


import os
import sys
import argparse
import socket
import select
import random
import time
import json
import traceback
import functools
import datetime

redis_lock_key = '{__rediser_cluster_lock_key6853__}'
redis_lock_key_ttl = 300
redis_lock_key_migrate = redis_lock_key + 'migrate'
redis_lock_key_tasks = redis_lock_key + 'tasks'
redis_lock_key_moving = redis_lock_key + 'moving'
redis_lock_key_finish = redis_lock_key + 'finish'

crc16tab = [
    0x0000,0x1021,0x2042,0x3063,0x4084,0x50a5,0x60c6,0x70e7,
    0x8108,0x9129,0xa14a,0xb16b,0xc18c,0xd1ad,0xe1ce,0xf1ef,
    0x1231,0x0210,0x3273,0x2252,0x52b5,0x4294,0x72f7,0x62d6,
    0x9339,0x8318,0xb37b,0xa35a,0xd3bd,0xc39c,0xf3ff,0xe3de,
    0x2462,0x3443,0x0420,0x1401,0x64e6,0x74c7,0x44a4,0x5485,
    0xa56a,0xb54b,0x8528,0x9509,0xe5ee,0xf5cf,0xc5ac,0xd58d,
    0x3653,0x2672,0x1611,0x0630,0x76d7,0x66f6,0x5695,0x46b4,
    0xb75b,0xa77a,0x9719,0x8738,0xf7df,0xe7fe,0xd79d,0xc7bc,
    0x48c4,0x58e5,0x6886,0x78a7,0x0840,0x1861,0x2802,0x3823,
    0xc9cc,0xd9ed,0xe98e,0xf9af,0x8948,0x9969,0xa90a,0xb92b,
    0x5af5,0x4ad4,0x7ab7,0x6a96,0x1a71,0x0a50,0x3a33,0x2a12,
    0xdbfd,0xcbdc,0xfbbf,0xeb9e,0x9b79,0x8b58,0xbb3b,0xab1a,
    0x6ca6,0x7c87,0x4ce4,0x5cc5,0x2c22,0x3c03,0x0c60,0x1c41,
    0xedae,0xfd8f,0xcdec,0xddcd,0xad2a,0xbd0b,0x8d68,0x9d49,
    0x7e97,0x6eb6,0x5ed5,0x4ef4,0x3e13,0x2e32,0x1e51,0x0e70,
    0xff9f,0xefbe,0xdfdd,0xcffc,0xbf1b,0xaf3a,0x9f59,0x8f78,
    0x9188,0x81a9,0xb1ca,0xa1eb,0xd10c,0xc12d,0xf14e,0xe16f,
    0x1080,0x00a1,0x30c2,0x20e3,0x5004,0x4025,0x7046,0x6067,
    0x83b9,0x9398,0xa3fb,0xb3da,0xc33d,0xd31c,0xe37f,0xf35e,
    0x02b1,0x1290,0x22f3,0x32d2,0x4235,0x5214,0x6277,0x7256,
    0xb5ea,0xa5cb,0x95a8,0x8589,0xf56e,0xe54f,0xd52c,0xc50d,
    0x34e2,0x24c3,0x14a0,0x0481,0x7466,0x6447,0x5424,0x4405,
    0xa7db,0xb7fa,0x8799,0x97b8,0xe75f,0xf77e,0xc71d,0xd73c,
    0x26d3,0x36f2,0x0691,0x16b0,0x6657,0x7676,0x4615,0x5634,
    0xd94c,0xc96d,0xf90e,0xe92f,0x99c8,0x89e9,0xb98a,0xa9ab,
    0x5844,0x4865,0x7806,0x6827,0x18c0,0x08e1,0x3882,0x28a3,
    0xcb7d,0xdb5c,0xeb3f,0xfb1e,0x8bf9,0x9bd8,0xabbb,0xbb9a,
    0x4a75,0x5a54,0x6a37,0x7a16,0x0af1,0x1ad0,0x2ab3,0x3a92,
    0xfd2e,0xed0f,0xdd6c,0xcd4d,0xbdaa,0xad8b,0x9de8,0x8dc9,
    0x7c26,0x6c07,0x5c64,0x4c45,0x3ca2,0x2c83,0x1ce0,0x0cc1,
    0xef1f,0xff3e,0xcf5d,0xdf7c,0xaf9b,0xbfba,0x8fd9,0x9ff8,
    0x6e17,0x7e36,0x4e55,0x5e74,0x2e93,0x3eb2,0x0ed1,0x1ef0
]

def crc16(buf):
    crc = 0
    for c in buf:
        v = ord(c)
        crc = ((crc<<8) ^ crc16tab[((crc>>8) ^ v) & 0x00FF]) & 0xFFFF
    return crc

def timestamp():
    return int(time.time())

def get_unique_id():
    hostname = socket.gethostname()
    random = ''.join(['%02X'%ord(i) for i in os.urandom(8)])
    now = datetime.datetime.now()
    return '_'.join([hostname, random, now.strftime('%Y%m%d%H%M%S')])

def str_or_repr(v):
    try:
        return str(v)
    except:
        return repr(v)

def split_addr(addr):
    try:
        idx = addr.find('@')
        if idx > 0:
            addr = addr[:idx]
        idx = addr.rfind(':')
        return (addr[:idx], int(addr[idx+1:]))
    except:
        raise Exception('invalid address(%s)' % addr)

def tprint(*args):
    if len(args) <= 1:
        sys.stdout.write('%s %s\n' % (time.strftime('%Y-%m-%d %H:%M:%S'), args[0] if len(args) == 1 else ''))
        sys.stdout.flush()
        return
    tag = args[0].lower()
    if os.isatty(sys.stdout.fileno()):
        if tag in ('error', 'fail', 'pfail', 'conflict', 'unassign'):
            tag = '\033[31m%s\033[0m' % args[0]
        elif tag in ('warn'):
            tag = '\033[34m%s\033[0m' % args[0]
        elif tag in ('ok', 'succ', 'pass'):
            tag = '\033[32m%s\033[0m' % args[0]
        else:
            tag = args[0]
    sys.stdout.write('%s %s %s\n' % (time.strftime('%Y-%m-%d %H:%M:%S'), tag, ' '.join([str(i) for i in args[1:]])))
    sys.stdout.flush()

class ClusterSlotState:
    stable = 0
    importing = 1
    migrating = 2

class Client(object):

    class ErrorBase(Exception):
        def __init__(self, *args, **kwargs):
            super(Client.ErrorBase, self).__init__(*args, **kwargs)

    class RespError(ErrorBase):
        def __init__(self, *args, **kwargs):
            super(Client.RespError, self).__init__(*args, **kwargs)

    class ProtocolError(ErrorBase):
        def __init__(self, *args, **kwargs):
            super(Client.ProtocolError, self).__init__(*args, **kwargs)

    class EmptyRecvError(ErrorBase):
        def __init__(self, *args, **kwargs):
            super(Client.EmptyRecvError, self).__init__(*args, **kwargs)

    class ConnBusyError(ErrorBase):
        def __init__(self, *args, **kwargs):
            super(Client.ConnBusyError, self).__init__(*args, **kwargs)

    def __init__(self, host='127.0.0.1', port=6379, db=0, password=None, timeout=None):
        self.family = socket.AF_UNIX if port==None else socket.AF_INET
        self.timeout = timeout
        self.addr = host if port==None else (host, port)
        self.db = db
        self.password = password
        self.conn = None
        self.sent = 0
        self.buf = ''

    def __repr__(self):
        return '<Client(addr=%s)>' % str(self.addr)

    def close(self):
        self.conn = None
        self.sent = 0
        self.buf = ''

    def _conn(self):
        if self.conn:
            return self.conn
        self.conn = socket.socket(self.family, socket.SOCK_STREAM)
        self.conn.settimeout(self.timeout)
        self.conn.connect(self.addr)
        if self.password != None:
            self.call('auth', self.password)
        if self.db > 0:
            self.call('select', self.db)
        return self.conn

    @staticmethod
    def _parse(buf):
        if len(buf) == 0:
            return 0, None
        c = buf[0]
        if c == '+':
            idx = buf.find('\r\n')
            if idx < 0:
                return 0, None
            return idx + 2, buf[1:idx]
        elif c == '-':
            idx = buf.find('\r\n')
            if idx < 0:
                return 0, None
            return idx + 2, Client.RespError(buf[1:idx])
        elif c == ':':
            idx = buf.find('\r\n')
            if idx < 0:
                return 0, None
            return idx + 2, int(buf[1:idx])
        elif c == '$':
            idx = buf.find('\r\n')
            if idx < 0:
                return 0, None
            n = int(buf[1:idx])
            if n < 0:
                return idx + 2, None
            idx += 2
            if n + 2 > len(buf) - idx:
                return 0, None
            if buf[idx+n:idx+n+2] != '\r\n':
                raise Client.ProtocolError, 'Bulk strings no end valid'
            return idx + n + 2, buf[idx:idx+n]
        elif c == '*':
            idx = buf.find('\r\n')
            if idx < 0:
                return 0, None
            n = int(buf[1:idx])
            if n < 0:
                raise Client.ProtocolError, 'array response length invalid:%d' % n
            idx += 2
            res = []
            while len(res) < n:
                i, r = Client._parse(buf[idx:])
                if i == 0:
                    return 0, None
                res.append(r)
                idx += i
            return idx, res
        else:
            raise Client.ProtocolError, 'unknown response header:' + repr(buf[0])
        return 0, None

    def send(self, *args):
        if len(args) == 0:
            raise ValueError, 'args length is 0'
        buf = '*%d\r\n' % len(args)
        for i in args:
            s = str(i)
            buf += '$%d\r\n%s\r\n' % (len(s), s)
        try:
            n = 0
            while n < len(buf):
                n += self._conn().send(buf[n:])
            self.sent += 1
        except:
            self.close()
            raise

    def recv(self, raise_resp_error=True):
        if self.sent == 0:
            raise Client.EmptyRecvError, 'no pend sent command'
        while True:
            idx = 0
            res = None
            try:
                if len(self.buf) > 0:
                    idx, res = Client._parse(self.buf)
                if idx == 0:
                    buf = self._conn().recv(16384)
                    self.buf += buf
                    idx, res = Client._parse(self.buf)
            except:
                self.close()
                raise
            if idx > 0:
                self.buf = self.buf[idx:]
                self.sent -= 1
                if raise_resp_error and isinstance(res, Client.RespError):
                    raise res
                return res

    def recvall(self, raise_resp_error=True):
        ret = []
        while self.sent > 0:
            r = self.recv(raise_resp_error)
            ret.append(r)
        return ret

    def call(self, *args):
        if self.sent > 0:
            raise Client.ConnBusyError, 'some command exists'
        self.send(*args)
        return self.recv()

class ClusterClient(object):
    def __init__(self, addrs, password=None, timeout=None):
        self.password = password
        self.timeout = timeout
        self.addrs = addrs
        self.conns = {}
        self.slots = [None] * 16384
        self.sent = []

    def close(self):
        for c in self.sent:
            c.close()
        self.sent = []

    def _conn_by_addr(self, addr, slot = None):
        c = self.conns.get(addr, None)
        if not c:
            host, port = split_addr(addr)
            c = Client(host=host, port=int(port), password=self.password, timeout=self.timeout)
            self.conns[addr] = c
        if slot != None:
            self.slots[slot] = c
        return c

    def _conn(self, *args):
        c = None
        idx = None
        if len(args) > 1:
            key = str(args[1])
            i = key.find('{')
            if i >= 0:
                j = key.find('}', i)
                if j > i + 1:
                    key = key[i+1 : j]
            idx = crc16(key) & 16383
        if idx != None and self.slots[idx]:
            return self.slots[idx]
        addr = self.addrs[random.randint(0, len(self.addrs) - 1)]
        return self._conn_by_addr(addr, idx)

    def send(self, *args):
        c = self._conn(*args)
        c.send(*args)
        self.sent.append(c)

    def recv(self, raise_resp_error=True):
        if len(self.sent) == 0:
            raise Client.EmptyRecvError, 'no pend sent command'
        c = self.sent[0]
        self.sent = self.sent[1:]
        return c.recv(raise_resp_error)

    def recvall(self, raise_resp_error=True):
        ret = []
        while len(self.sent) > 0:
            try:
                r = self.recv(raise_resp_error)
            except:
                self.close()
                raise
            ret.append(r)
        return ret

    def call(self, *args):
        if len(self.sent) > 0:
            raise Client.ConnBusyError, 'some command exists'
        trycnt = 0
        try:
            c = self._conn(*args)
            return c.call(*args)
        except Client.RespError as r:
            while True:
                if trycnt == 2:
                    raise
                trycnt += 1
                if r.message.startswith('MOVED'):
                    e = r.message.split()
                    if len(e) != 3:
                        raise
                    c = self._conn_by_addr(e[2], int(e[1]))
                    try:
                        return c.call(*args)
                    except Client.RespError as excp:
                        r = excp
                elif r.message.startswith('ASK'):
                    e = r.message.split()
                    if len(e) != 3:
                        raise
                    c = self._conn_by_addr(e[2], int(e[1]))
                    c.call('ASKING')
                    try:
                        return c.call(*args)
                    except Client.RespError as excp:
                        r = excp
                else:
                    raise

class Poll(object):
    def __init__(self):
        self.p = select.poll()
        self.conns = {}

    def size(self):
        return len(self.conns)

    def elements(self):
        return [c for _, c in self.conns.iteritems()]

    def register(self, c, read=False, write=False):
        evt = 0
        if read:
            evt |= select.POLLIN
        if write:
            evt |= select.POLLOUT
        r = self.p.register(c, evt)
        self.conns[c.fileno()] = c
        return r

    def unregister(self, c):
        if c.fileno() in self.conns:
            self.conns.pop(c.fileno())
            self.p.unregister(c)

    def modify(self, c, read=False, write=False):
        if c.fileno() not in self.conns:
            return
        evt = 0
        if read:
            evt |= select.POLLIN
        if write:
            evt |= select.POLLOUT
        return self.p.modify(c, evt)

    def poll(self, timeout=-1):
        r = self.p.poll(timeout)
        for i, evt in r:
            c = self.conns[i]
            read = True if evt & select.POLLIN else False
            write = True if evt & select.POLLOUT else False
            err = True if evt & (select.POLLERR|select.POLLHUP) else False
            c.handle(read, write, err)
        return len(r)

    def wait(self, timeout=-1):
        t = -1 if timeout == -1 else timeout * 1000
        while self.size() > 0:
            n = self.poll(t)
            if n == 0:
                for c in self.elements():
                    c.abort('connection io timeout')
                break

class AsyncClient(Client):
    Read = 1
    Write = 2
    unconnected = 0
    connecting = 1
    connected = 2

    def __init__(self, poll, host='127.0.0.1', port=1279, password=None):
        super(AsyncClient, self).__init__(host, port, password=password)
        self.poll = poll
        self.pend = []
        self.sent = []
        self.state = AsyncClient.unconnected
        self.event = 0

    def _set_event(self, read=None, write=None):
        evt = 0
        if read == None:
            evt |= self.event & AsyncClient.Read
        elif read:
            evt |= AsyncClient.Read
        if write == None:
            evt |= self.event & AsyncClient.Write
        elif write:
            evt |= AsyncClient.Write
        if evt != self.event:
            if evt:
                if self.event:
                    self.poll.modify(self, evt & AsyncClient.Read, evt & AsyncClient.Write)
                else:
                    self.poll.register(self, evt & AsyncClient.Read, evt & AsyncClient.Write)
            else:
                self.poll.unregister(self)
            self.event = evt

    def fileno(self):
        return self.conn.fileno()

    def call(self, cb, *args):
        if len(args) == 0:
            raise ValueError, 'args length is 0'
        buf = '*%d\r\n' % len(args)
        for i in args:
            s = str(i)
            buf += '$%d\r\n%s\r\n' % (len(s), s)
        self.pend.append([cb, buf, 0])
        try:
            self._send()
        except Exception as excp:
            self._excp(excp)

    def abort(self, res):
        self._excp(Exception(res))

    def _send(self):
        if not self.conn:
            c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            c.setblocking(False)
            try:
                c.connect(self.addr)
            except socket.error as err:
                if err.errno != socket.errno.EINPROGRESS:
                    raise
            self.conn = c
            self.state = AsyncClient.connecting
            self._set_event(write=True)
            if self.password != None:
                buf = '*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n' % (len(self.password), self.password)
                self.pend.insert(0, [None, buf, 0])
        if self.state == AsyncClient.connected:
            try:
                while len(self.pend) > 0:
                    m = self.pend[0]
                    n = self.conn.send(m[1][m[2]:])
                    m[2] += n
                    if m[2] >= len(m[1]):
                        self.sent.append(m)
                        self.pend = self.pend[1:]
            except socket.error as err:
                if err.errno not in (socket.errno.EAGAIN, socket.errno.EWOULDBLOCK, socket.errno.EINTR):
                    raise
        self._set_event(True, len(self.pend)>0)

    def _recv(self):
        try:
            while True:
                buf = self.conn.recv(16384)
                self.buf += buf
                while len(self.buf) > 0:
                    n, res = self._parse(self.buf)
                    if n > 0:
                        cb = self.sent[0][0]
                        if cb:
                            cb(res)
                        self.sent = self.sent[1:]
                        self.buf = self.buf[n:]
                    else:
                        break
        except socket.error as err:
            if err.errno not in (socket.errno.EAGAIN, socket.errno.EWOULDBLOCK, socket.errno.EINTR):
                raise
        if len(self.sent) + len(self.pend) == 0:
            self._set_event(False, False)

    def _excp(self, excp):
        reqs = self.sent + self.pend
        for req in reqs:
            if req[0]:
                req[0](excp)
        if self.conn:
            self._set_event(False, False)
            self.conn = None
        self.sent = []
        self.pend = []
        self.buf = ''
        self.state = AsyncClient.unconnected

    def handle(self, read, write, err):
        if err:
            self._excp(Exception('recv error event'))
            return
        if write and self.state == AsyncClient.connecting:
            self.state = AsyncClient.connected
        try:
            if write:
                self._send()
            if read:
                self._recv()
        except socket.error as err:
            self._excp(err)
        except Client.ErrorBase as cerr:
            self._excp(cerr)

class Inst(object):
    def __init__(self, addr, poll=None, password=None):
        self.addr = addr
        self.client = None
        self.async_client = None
        self.poll = poll
        self.password = password

    def call(self, *args):
        if self.client == None:
            host, port = split_addr(self.addr)
            self.client = Client(host, port, password=self.password, timeout=60)
        return self.client.call(*args)

    def async_call(self, cb, *args):
        if self.async_client == None:
            host, port = split_addr(self.addr)
            self.async_client = AsyncClient(self.poll, host, port, password=self.password)
        return self.async_client.call(cb, *args)

class ClusterInst(Inst):
    def __init__(self, addr, poll=None, password=None):
        super(ClusterInst, self).__init__(addr, poll, password)
        self.src = None
        self.reset()

    def reset(self):
        self.id = None
        self.flags = None
        self.role = None
        self.fail = None
        self.noaddr = None
        self.handshake = None
        self.nofalgs = None
        self.masterid = None
        self.master = None
        self.connected = None
        self.slots = []
        self.importing_slots = []
        self.migrating_slots = []
        self.insts = []
        self.msgs = []

    def set_node_line(self, line):
        e = line.split()
        self.id = e[0]
        flags = []
        for flag in e[2].split(','):
            if len(flag) == 0 or flag in set(['myself','master','slave']):
                continue
            else:
                flags.append(flag)
        flags.sort()
        if e[2].find('master') >= 0:
            self.role = 'master'
        elif e[2].find('slave') >= 0:
            self.role = 'slave'
        if e[2].find('fail?') >= 0:
            self.fail = 'pfail'
        elif e[2].find('fail') >= 0:
            self.fail = 'fail'
        if e[2].find('handshake') >= 0:
            self.handshake = True
        if e[2].find('noaddr') >= 0:
            self.noaddr = True
        if e[2].find('noflags') >= 0:
            self.noflags = True
        if self.role:
            flags.insert(0, self.role)
        self.flags = ','.join(flags) if len(flags) > 0 else ''
        self.masterid = e[3]
        self.master = None
        self.connected = e[7] == 'connected'
        for slot in e[8:]:
            if slot.find('<') >= 0:
                num, id = slot.split('-<-')
                self.importing_slots.append((int(num[1:]), id[:-1]))
            elif slot.find('>') >= 0:
                num, id = slot.split('->-')
                self.migrating_slots.append((int(num[1:]), id[:-1]))
            elif slot.find('-') >= 0:
                start, end = slot.split('-')
                self.slots += range(int(start), int(end) + 1)
            else:
                self.slots.append(int(slot))

    def set_by_client(self):
        self.src = self.addr
        nodes = ''
        try:
            nodes = self.call('cluster', 'nodes')
        except Exception as excp:
            self.msgs.append(('warn', '%s cluster nodes exception:%s' % (self.addr, str(excp))))
            return
        self._cb_cluster_nodes(nodes)

    def set_by_async_client(self):
        self.src = self.addr
        self.async_call(self._cb_cluster_nodes, 'cluster', 'nodes')

    def _cb_cluster_nodes(self, nodes):
        if isinstance(nodes, Exception):
            self.msgs.append(('warn', '%s cluster nodes exception:%s' % (self.addr, str(nodes))))
            return
        self.reset()
        lines = nodes.split('\n')
        id_map = {}
        for line in lines:
            inst = self
            if line.find('myself') >= 0:
                self.set_node_line(line)
            else:
                e = line.split()
                if len(e) >= 8:
                    addr = e[1]
                    idx = addr.find('@')
                    if idx > 0:
                        addr = addr[:idx]
                    inst = ClusterInst(addr)
                    inst.set_node_line(line)
                    inst.src = self.addr
                    self.insts.append(inst)
            id_map[inst.id] = inst
        self.master = id_map.get(self.masterid, None)
        for i in self.insts:
            i.master = id_map.get(i.masterid, None)

    def has_slot(self, importing=True, migrating=True):
        if len(self.slots) > 0:
            return True
        if importing and len(self.importing_slots) > 0:
            return True
        if migrating and len(self.migrating_slots) > 0:
            return True
        return False

def slot_array_merge(slots, f=lambda v:v):
    '''
    slots: [value, value,...]
    return: [(slot, value)|(begin_slot, end_slot, value),...]
    '''
    ret = []
    def merge(begin, end):
        if begin < end:
            return (begin, end, slots[begin])
        else:
            return (begin, slots[begin])
    begin = 0
    end = 0
    value = f(slots[0])
    for i in xrange(1, len(slots)):
        v = f(slots[i])
        if value == v:
            end = i
        else:
            ret.append(merge(begin, end))
            begin = end = i
            value = v
    ret.append(merge(begin, end))
    return ret

class Shard(object):
    def __init__(self):
        self.insts = []
        self.slot_masters = []
        self.null_masters = []
        self.slaves = []
        self.master = None
        self.msgs = []

class InstsController(object):
    def __init__(self, addrs, password=None):
        self.poll = Poll()
        self.insts = {}
        for addr in addrs:
            self.insts[addr] = Inst(addr, self.poll, password=password)

    def call(self, *args, **kwargs):
        r = {}
        def cb(res, inst):
            r[inst.addr] = res
        for _, inst in self.insts.iteritems():
            inst.async_call(functools.partial(cb, inst=inst), *args)
        timeout = kwargs.get('timeout', 60)
        self.poll.wait(timeout)
        return r

class TaskMode:
    assign  = 1 << 0
    migrate = 1 << 1
    fix     = 1 << 2

class MigrateSlotTask(object):
    def __init__(self, dst, slot, src, cli, taskid, mode, pipeline=10, timeout=100):
        self.dst = dst
        self.host, self.port = split_addr(dst.addr)
        self.slot = slot
        self.src = src
        self.cli = cli
        self.taskid = taskid
        self.mode = mode
        self.pipeline = pipeline
        self.timeout = timeout * 1000
        self.total = 0
        self.count = 0
        self.finished = None
        self.begin = timestamp()
        self.last = 0

    def start(self, cb_finish):
        tprint('start migrate slot %d from %s to %s' % (self.slot, self.src.addr, self.dst.addr))
        self.cb_finish = cb_finish
        if self.mode == TaskMode.fix:
            self.src.async_call(self._cb_get_keys, 'cluster', 'setslot', self.slot, 'importing', self.src.id)
        else:
            self.dst.async_call(self._cb_set_importing, 'cluster', 'setslot', self.slot, 'importing', self.src.id)
        self.src.async_call(self._cb_countkeysinslot, 'cluster', 'countkeysinslot', self.slot)

    def _cb_countkeysinslot(self, res):
        if isinstance(res, int):
            self.total = res
        else:
            self.total = 0

    def _cb_set_importing(self, res):
        if isinstance(res, Exception):
            self._finish(res)
            return
        self.src.async_call(self._cb_get_keys, 'cluster', 'setslot', self.slot, 'migrating', self.dst.id)

    def _cb_get_keys(self, res):
        if isinstance(res, Exception):
            self._finish(res)
            return
        self._get_keys()

    def _get_keys(self):
        now = timestamp()
        if now > self.last + 1:
            try:
                self.last = now
                tprint('migrate slot %d from %s to %s progress:%d/%d' % (self.slot, self.src.addr, self.dst.addr, self.count, self.total))
                if self.cli.call('expire', redis_lock_key_migrate, redis_lock_key_ttl) == 0:
                    self.taskid = ''
                    self._finish('error:migrate lock expire noexists')
                    return
                taskid = self.cli.call('get', redis_lock_key_migrate)
                if taskid != self.taskid:
                    oldid = self.taskid
                    self.taskid = taskid
                    self._finish('error:migrate taskid changed(%s -> %s)' % (oldid, taskid))
                    return
                self.cli.call('hset', redis_lock_key_moving, self.slot,
                               json.dumps({'count':self.count,
                                           'total':self.total,
                                           'src':self.src.addr,
                                           'dst':self.dst.addr,
                                           'start':self.begin,
                                           'timestamp':now}))
            except Exception as excp:
                tprint('warn', '%s migrate slot %d record state exception:%s' % (self.src.addr, self.slot, str(excp)))
        self.src.async_call(self._cb_getkeysinslot, 'cluster', 'getkeysinslot', self.slot, self.pipeline)

    def _cb_getkeysinslot(self, res):
        if isinstance(res, Exception):
            self._finish(res)
            return
        if not res:
            tprint('migrate slot %d from %s to %s progress:%d/%d' % (self.slot, self.src.addr, self.dst.addr, self.count, self.total))
            self._finish('ok')
            return
        self.src.async_call(functools.partial(self._cb_migrate, keys=res), 'migrate', self.host, self.port, '', 0, self.timeout, 'replace', 'keys', *res)

    def _cb_migrate(self, res, keys):
        if isinstance(res, Exception) and not isinstance(res, Client.RespError):
            self._finish(res)
            return
        self.count += len(keys)
        self._get_keys()

    def _finish(self, res):
        if isinstance(res, Exception):
            self.finished = 'error:' + str(res)
        else:
            self.finished = res
        if self.mode == TaskMode.fix and self.finished == 'ok':
            try:
                self.src.call('cluster', 'setslot', self.slot, 'stable')
            except Exception as excp:
                self.finished = 'error:' + str(excp)
        try:
            self.cli.call('hdel', redis_lock_key_moving, self.slot)
            self.cli.call('hset', redis_lock_key_finish, self.slot,
                           json.dumps({'count':self.count,
                                       'total':self.total,
                                       'src':self.src.addr,
                                       'dst':self.dst.addr,
                                       'finished':self.finished,
                                       'start':self.begin,
                                       'timestamp':timestamp()}))
        except:
            pass
        if self.cb_finish:
            self.cb_finish(self)

class MigrateSlotTaskFixer(object):
    def __init__(self, num, cc):
        self.num = num
        self.cc = cc
        self.tasks = {}
        self.last_task = None

    def add(self, t):
        if t.dst.addr not in self.tasks:#always commit first slot for an addr
            self._flush_last_task()
            self.tasks[t.dst.addr] = []
        if not self.last_task or self.last_task.dst.addr == t.dst.addr:
            self._commit(t)
            self.last_task = t
            return
        self.tasks[t.dst.addr].append(t)
        if len(self.tasks[t.dst.addr]) >= self.num:
            self._flush_last_task()
            for i in self.tasks[t.dst.addr]:
                self._commit(i)
            self.last_task = t
            self.tasks[t.dst.addr] = []

    def flush(self):
        for addr, tasks in self.tasks.iteritems():
            if len(tasks) == 0:
                continue
            self._flush_last_task()
            for t in tasks:
                self._commit(t)
            self.last_task = tasks[-1]

    def _flush_last_task(self):
        if not self.last_task:
            return
        succ = True
        t = self.last_task
        tprint('wait commit slot %s to %s' % (t.slot, t.dst.addr))
        if not self._check(t):
            succ = False
            for i in xrange(0, 5):
                self._commit(t)
                time.sleep(0.8 * (i + 1))
                if self._check(t):
                    succ = True
                    break
        tag = 'ok' if succ else 'fail'
        tprint(tag, 'commit slot %s to %s' % (t.slot, t.dst.addr))
        self.last_task = None

    def _commit(self, t):
        cc = self.cc
        try:
            t.dst.call('cluster', 'setslot', t.slot, 'node', t.dst.id)
        except Exception as excp:
            tprint('warn', '%s cluster setslot %d node %s(%s) exception:%s' % (t.dst.addr, t.slot, t.dst.id, t.dst.addr, str(excp)))
        for addr, nodes in cc.nodes.iteritems():
            inst = nodes[0]
            if inst.role == 'master':
                def _cb_excp_warn(res, msg):
                    if isinstance(res, Exception):
                        tprint('warn', '%s exception:%s' % (msg, str(res)))
                inst.async_call(functools.partial(_cb_excp_warn, msg='%s cluster setslot %d node %s' % (inst.addr, t.slot, t.dst.addr)), 'cluster', 'setslot', t.slot, 'node', t.dst.id)
                if t.mode == TaskMode.fix:
                    inst.async_call(functools.partial(_cb_excp_warn, msg='%s cluster setslot %d stable' % (inst.addr, t.slot)), 'cluster', 'setslot', t.slot, 'stable')
        cc.poll.wait(60)
        if t.mode == TaskMode.fix:
            def _cb_delslots(res, inst):
                if isinstance(res, Exception):
                    tprint('warn', '%s cluster delslots %d exception:%s' % (inst.addr, t.slot, str(res)))
            for addr, nodes in cc.nodes.iteritems():
                inst = nodes[0]
                if inst.role == 'slave':
                    inst.async_call(functools.partial(_cb_delslots, inst=inst), 'cluster', 'delslots', t.slot)
            cc.poll.wait(60)

    def _check(self, t):
        cc = self.cc
        res = cc.call('cluster', 'nodes')
        for addr, nodes in res.iteritems():
            if isinstance(nodes, Exception):
                continue
            idx = nodes.find(t.dst.addr)
            if idx < 0:
                continue
            end = nodes.find('\n', idx)
            line = nodes[idx:end] if end > 0 else nodes[idx:]
            items = line.split()
            items.reverse()
            found = False
            for seg in items:
                if seg[0] == '[': #importing or migrating slot
                    continue
                elif seg[0] < '0' or seg[0] > '9':
                    break
                e = seg.split('-')
                if len(e) == 1 or len(e) > 2:
                    if int(e[0]) == t.slot:
                        found = True
                        break
                elif len(e) == 2:
                    if int(e[0]) <= t.slot and t.slot <= int(e[1]):
                        found = True
                        break
            if not found:
                return False
        return True

class ClusterController(object):
    def __init__(self):
        self.poll = Poll()
        self.client = None
        self.nodes = {}
        self.idmap = {}

    def set_by_addrs(self, addrs, timeout=5, password=None):
        nodes = {}
        all = set(addrs)
        visited = set()
        while len(visited) < len(all):
            pend = []
            for i in all.difference(visited):
                visited.add(i)
                inst = ClusterInst(i, poll=self.poll, password=password)
                pend.append(inst)
                inst.set_by_async_client()
                if i in nodes:
                    nodes[i].insert(0, inst)
                else:
                    nodes[i] = [inst]

            self.poll.wait(timeout)

            for inst in pend:
                if not inst.id:
                    continue
                self.idmap[inst.id] = inst.addr
                for node in inst.insts:
                    self.idmap[node.id] = node.addr
                    all.add(node.addr)
                    if node.addr in nodes:
                        nodes[node.addr].append(node)
                    else:
                        nodes[node.addr] = [node]
        for addr, insts in nodes.iteritems():
            srcs = set([i.src for i in insts])
            for i in all.difference(srcs):
                if not nodes[i][0].id:
                    continue
                inst = ClusterInst(addr, password=password)
                inst.src = i
                insts.append(inst)
        self.nodes = nodes
        self.client = ClusterClient(nodes.keys(), timeout=timeout, password=password)

    def view(self):
        '''
        return: {'insts':insts, 'slots':slots, 'unstable_slots':unstable_slots, 'excp_insts':excp_insts, 'inst_nodes':inst_nodes}
            insts: {'addr':[[ClusterInst,...],,,]} for an addr
            slots: [{'owner':[ClusterInst,...]},...], len(slots)==16384, ClusterInst is supporter who thinks slot in addr
            unstable_slots: {slot:{'importing':[[dst, srcid, src],...], 'migrating':[[src, dstid, dst],...]},...}
            excp_insts: [ClusterInst,...]
        '''
        def identify(i):
            return 'addr=%s id=%s role=%s flags=%s masterid=%s slots=%s' % (
                    i.addr, i.id, i.role, str(i.flags), i.masterid, str(i.slots))
        insts = {}
        excp_insts = []
        slots = [None] * 16384
        unstable_slots = {}
        for addr, nodes in self.nodes.iteritems():
            view = {}
            for i in nodes:
                #if not i.id:
                #    excp_insts.append(i)
                #    continue
                k = identify(i)
                if k in view:
                    view[k].append(i)
                else:
                    view[k] = [i]
                tttt__='''
                for slot in i.slots:
                    if slots[slot] == None:
                        slots[slot] = {}
                    if i.addr in slots[slot]:
                        slots[slot][i.addr].append(i.src)
                    else:
                        slots[slot][i.addr] = [i.src]'''
            if nodes[0].id:
                slotset = set(xrange(0, 16384))
                sinsts = [nodes[0]] + nodes[0].insts
                def assign_slot(slot, addr, src):
                    if slots[slot] == None:
                        slots[slot] = {addr:[src]}
                    elif addr in slots[slot]:
                        slots[slot][addr].append(src)
                    else:
                        slots[slot][addr] = [src]
                for i in sinsts:
                    for slot in i.slots:
                        assign_slot(slot, i.addr, i.src)
                        if slot in slotset:
                            slotset.remove(slot)
                for slot in slotset:
                    assign_slot(slot, None, nodes[0].src)
            insts[addr] = [v for _, v in view.iteritems()]
            for slot in nodes[0].importing_slots:
                if slot[0] not in unstable_slots:
                    unstable_slots[slot[0]] = {'importing':[], 'migrating':[]}
                unstable_slots[slot[0]]['importing'].append((nodes[0].addr, slot[1], self.idmap.get(slot[1], 'noaddr')))
            for slot in nodes[0].migrating_slots:
                if slot[0] not in unstable_slots:
                    unstable_slots[slot[0]] = {'importing':[], 'migrating':[]}
                unstable_slots[slot[0]]['migrating'].append((nodes[0].addr, slot[1], self.idmap.get(slot[1], 'noaddr')))

        return {'insts':insts, 'slots':slots, 'unstable_slots':unstable_slots, 'excp_insts':excp_insts}


    def info(self, timeout=60):
        '''
        addrs: a list of instance address, eg:['10.2.3.4:6379', '10.2.3.5:7200']
        return: a map, eg:{'cluster_state':{state:[ClusterInst,...],...}}
        '''
        m = {}
        excps = {}

        def cb(info, inst):
            if isinstance(info, Exception):
                k = str(info)
                if k in excps:
                    excps[k].append(inst)
                else:
                    excps[k] = [inst]
                return
            lines = info.split()
            for line in lines:
                e = line.split(':')
                if len(e) != 2:
                    continue
                k, v = e
                r = m.get(k, {})
                if v in r:
                    r[v].append(inst)
                else:
                    r[v] = [inst]
                if k in m:
                    m[k].update(r)
                else:
                    m[k] = r

        nodes = self.nodes
        for addr, insts in nodes.iteritems():
            inst = insts[0]
            inst.async_call(functools.partial(cb, inst=inst), 'cluster', 'info')

        self.poll.wait(timeout)

        if len(excps) > 0:
            m['Exception'] = excps

        return m

    def init(self, shards, ignore_excp_inst=False):
        '''
        shards:[[master,slave...],...]
        '''
        state = True
        msgs = []
        ss = []
        insts = []
        pairs = set()
        for s in shards:
            shard = Shard()
            for i in s:
                role = None
                slots = []
                inst = self.nodes[i][0]
                insts.append(inst)
                if not inst.id:
                    msgs += inst.msgs
                    if not ignore_excp_inst:
                        state = False
                for node in self.nodes[i]:
                    if not node.id:
                        continue
                    pairs.add(node.src + '-' + node.addr)
                    slots += node.slots
                    if role == None:
                        role = node.role
                    elif role != node.role and node.role:
                        state = False
                        msgs.append(('warn', '%s role conflict' % i))
                slots = list(set(slots))
                slots.sort()
                if role == 'master':
                    if len(slots) > 0:
                        shard.slot_masters.append(inst)
                    else:
                        shard.null_masters.append(inst)
                elif role == 'slave':
                    shard.slaves.append(inst)
            if len(shard.slot_masters) > 1:
                state = False
                msgs.append(('warn', 'shard has multi master:%s' % ','.join([i.addr for i in shard.slot_masters])))
            elif len(shard.slot_masters) == 1:
                shard.master = shard.slot_masters[0]
            elif len(shard.null_masters) > 0:
                shard.master = shard.null_masters[0]
            ss.append(shard)

        if not state:
            return state, msgs

        for s in shards:
            for i in xrange(0, len(s)):
                src = s[i]
                for j in xrange(i + 1, len(s)):
                    dst = s[j]
                    inst = self.nodes[src][0]
                    if (src + '-' + dst) in pairs or (dst + '-' + src) in pairs:
                        continue
                    try:
                        host, port = split_addr(dst)
                        tprint('info', '%s meet %s' % (src, dst))
                        inst.call('cluster', 'meet', host, port)
                    except Exception as excp:
                        tprint('info', '%s meet %s exception:%s' % (src, dst, str(excp)))
        try_cnt = 0
        exe_cnt = 0
        all_meet = False
        while try_cnt < 16 and exe_cnt < 3 and not all_meet:
            try_cnt += 1
            idx = random.randint(0, len(insts) - 1)
            src = insts[idx]
            if not src.id:
                continue
            exe_cnt += 1
            all_meet = True
            for dst in insts:
                if (src.addr + '-' + dst.addr) in pairs or (dst.addr + '-' + src.addr) in pairs:
                    continue
                try:
                    all_meet = False
                    host, port = split_addr(dst.addr)
                    tprint('info', '%s meet %s' % (src.addr, dst.addr))
                    src.call('cluster', 'meet', host, port)
                except Exception as excp:
                    tprint('info', '%s meet %s exception:%s' % (src.addr, dst.addr, str(excp)))

        if exe_cnt < 1:
            msgs.append(('error', 'cluster meet fail'))
            return False, msgs
        nshard = len(shards)
        slots = set()
        for s in ss:
            master = s.master
            if not master:
                continue
            slots = slots.union(set(master.slots))
            for i in s.null_masters:
                if i == master:
                    continue
                tprint('info', '%s replicate %s(%s)' % (i.addr, master.addr, master.id))
                try:
                    trycnt = 0
                    while True:
                        trycnt += 1
                        try:
                            i.call('cluster', 'replicate', master.id)
                            break
                        except Client.RespError as r:
                            if trycnt < 5 and r.message.startswith('ERR Unknown node'):
                                time.sleep(0.1)
                                tprint('info', '%s retry replicate %s(%s)' % (i.addr, master.addr, master.id))
                                continue
                            raise
                except Exception as excp:
                    msg = '%s replicate %s(%s) exception:%s' % (i.addr, master.addr, master.id, str(excp))
                    msgs.append(('error', msg))
        if len(slots) == 16384:
            return state, msgs
        step = 16384 / nshard
        remain = 16384 % nshard
        end = 0
        for s in ss:
            master = s.master
            start = end
            end += step
            if remain > 0:
                end += 1
                remain -= 1
            free_slots = set(xrange(start, end)).difference(slots)
            if master:
                tprint('info', '%s addslots ...' % master.addr)
            elif len(free_slots) == 0:
                state = False
                msgs.append(('error', 'slots %s assign to (%s) no master' % (str(free_slots), ','.join([i.addr for i in s]))))
                continue
            try:
                master.call('cluster', 'addslots', *list(free_slots))
            except:
                for slot in free_slots:
                    try:
                        master.call('cluster', 'addslots', slot)
                    except Exception as excp:
                        msgs.append(('warn', '%s addslots %d exception:%s' % (master.addr, slot, str(excp))))
        return state, msgs

    def prepare_migrate_slots(self, addr_slots, fix=False, force_lock=False):
        '''
        addr_slots:{'addr':[slot,...],...}
        '''
        state = True
        msgs = []
        view = self.view()
        slots = view['slots']
        slot0 = slots[0]
        if slot0 == None or len(slot0) != 1 or not slot0.keys()[0]:
            msgs.append(('error', 'must keep sure slot 0 is available in migrate slots operator'))
            return {'state':False, 'msgs':msgs}
        taskid = get_unique_id()
        start = timestamp()
        cli = self.client
        try:
            if force_lock:
                r = cli.call('set', redis_lock_key_migrate, taskid, 'EX', redis_lock_key_ttl)
            else:
                r = cli.call('set', redis_lock_key_migrate, taskid, 'EX', redis_lock_key_ttl, 'NX')
            if r == None:
                id = ''
                try:
                    id = cli.call('get', redis_lock_key_migrate)
                except:
                    pass
                msgs.append(('error', 'other migrate task(%s) is running' % id))
                return {'state':False, 'msgs':msgs}
        except Exception as excp:
            msgs.append(('error', 'get lock for migrate fail:%s' % str(excp)))
            return {'state':False, 'msgs':msgs}

        unstable_slots = view['unstable_slots']
        slot_used = {}
        mig_slots = {}
        for addr, s in addr_slots.iteritems():
            insts = self.nodes[addr]
            inst = insts[0]
            tasks = {}
            if not inst.id:
                state = False
                msgs += inst.msgs
            for i in insts:
                if i.role != 'master':
                    state = False
                    msgs.append(('error', '%s is not master from %s view' % (addr, i.src)))
            for slot in s:
                if slot in slot_used:
                    state = False
                    slot_used[slot].append(addr)
                    continue
                slot_used[slot] = [addr]
                importing = []
                migrating = []
                if slot in unstable_slots:
                    importing = unstable_slots[slot]['importing']
                    migrating = unstable_slots[slot]['migrating']
                owners = slots[slot]
                if owners and None in owners:
                    owners.pop(None)
                if owners == None:
                    if not fix:
                        state = False
                        msgs.append(('error', 'slot %d current unassign to any node' % (slot,)))
                    else:
                        tasks[slot] = {'mode':TaskMode.assign}
                elif len(owners) == 1:
                    owner = owners.keys()[0]
                    st = True
                    m = []
                    for i in importing:
                        if i[0] != addr:
                            st = False
                            m.append(('error', '%s think slot %d is importing from %s' % (i[0], slot, i[2])))
                    for i in migrating:
                        if i[2] != 'noaddr' and i[2] != addr:
                            st = False
                            m.append(('error', '%s think slot %d is migrating to %s' % (i[0], slot, i[2])))
                    if st and owner == addr and len(importing) + len(migrating) > 0:
                        st = False
                        m.append(('warn', 'slot %d in %s, but some exists importing/migrating mark' % (slot, addr)))
                    if st:
                        if owner == addr:
                            msgs.append(('ok', 'slot %d already in %s' % (slot, addr)))
                        else:
                            tasks[slot] = {'mode':TaskMode.migrate, 'srcs':[owner]}
                    elif not fix:
                        state = False
                        msgs += m
                    else:
                        srcs = set()
                        for i in importing + migrating:
                            srcs.add(i[0])
                            srcs.add(i[2])
                        srcs.discard(addr)
                        srcs.discard('noaddr')
                        tasks[slot] = {'mode':TaskMode.fix, 'srcs':list(srcs)}
                else: #len(owner) > 1
                    if not fix:
                        state = False
                        msgs.append(('error', 'slot %d assign is conflict:%s' % (slot, ','.join([str(i) for i in owners]))))
                    else:
                        srcs = set(owners.keys())
                        for i in importing + migrating:
                            srcs.add(i[0])
                            srcs.add(i[2])
                        srcs.discard(addr)
                        srcs.discard('noaddr')
                        tasks[slot] = {'mode':TaskMode.fix, 'srcs':list(srcs)}

            if len(tasks) > 0:
                mig_slots[addr] = tasks
        if not state:
            for slot, addrs in slot_used.iteritems():
                if len(addrs) > 1:
                    msgs.append(('error', 'slot %d be specified to multi instances:%s' % (slot, ','.join(addrs))))
            return {'state':state, 'msgs':msgs}

        if len(mig_slots) == 0:
            try:
                # don't use: cli.call('del', redis_lock_key_migrate, redis_lock_key_moving, redis_lock_key_finish)
                # when slot 0 in migrating state, this call maybe fail
                cli.call('del', redis_lock_key_migrate)
                cli.call('del', redis_lock_key_moving)
                cli.call('del', redis_lock_key_finish)
            except:
                pass
            return {'state':state, 'msgs':msgs, 'taskid':taskid, 'addr_slots':mig_slots}

        try:
            cli.call('expire', redis_lock_key_migrate, redis_lock_key_ttl)
            cli.call('del', redis_lock_key_moving)
            cli.call('del', redis_lock_key_finish)
            value = {'id':taskid, 'tasks':mig_slots, 'start':start}
            cli.call('hset', redis_lock_key_finish, 'task', json.dumps(value))
        except Exception as excp:
            traceback.print_exc()
            try:
                cli.call('del', redis_lock_key_migrate)
                cli.call('del', redis_lock_key_moving)
            except:
                pass
            msgs.append(('error', 'update lock for migrate fail:%s' % str(excp)))
            return {'state':False, 'msgs':msgs}
        return {'state':state, 'msgs':msgs, 'taskid':taskid, 'addr_slots':mig_slots}

    def migrate_slots(self, addr_slots, taskid, parellel_level='host', max_parellel=10, pipeline=10, timeout=100):
        '''
        addr_slots:{'addr':{slot:{'mode':TaskMode,'srcs':[addr,...]},...},...}
        '''
        total = sum([len(s) for addr, s in addr_slots.iteritems()])
        if total == 0:
            return
        try:
            id = self.client.call('get', redis_lock_key_migrate)
            if id != taskid:
                raise Exception('migrate slots taskid unmatch (%s, %s)' % (taskid, str_or_repr(id)))
        except Exception as excp:
            tprint('error', 'migrate slots check taskid fail:%s' % str(excp))
            raise
        level = lambda addr:':'.join(addr.split(':')[:-1])
        if parellel_level == 'inst':
            level = lambda addr:addr
        busy = {level(addr):0 for addr in self.nodes}
        tasks = set()
        count = [0]
        fails = []
        stop = [False]
        slot_finish = [False] * 16384
        slot_succ = [True] * 16384
        cc = ClusterController()
        cc.set_by_addrs(self.nodes.keys())

        for addr, s in addr_slots.iteritems():
            inst = self.nodes[addr][0]
            for slot, slot_task in s.iteritems():
                if slot_task['mode'] == TaskMode.assign:
                    count[0] += 1
                    try:
                        tprint('%s addslots %d' % (addr, slot))
                        inst.call('cluster', 'addslots', slot)
                    except Exception as excp:
                        tprint('error', 'assign slot %s to %s exception:%s' % (slot, addr, str(excp)))
                        fails.append((slot, 'assign to %s exception:%s' % (addr, str(excp))))

        info_mem = cc.call('info', 'memory')
        used_mem = {}
        for addr, info in info_mem.iteritems():
            mem = 0
            info = str(info)
            idx = info.find('used_memory:')
            if idx >= 0:
                idx += len('used_memory:')
                end = info.find('\n', idx)
                mem = int(info[idx:end])
            used_mem[addr] = mem

        addrs = addr_slots.keys()
        def addr_cmp(addr1, addr2):
            v1 = used_mem.get(addr1, 0)
            v2 = used_mem.get(addr2, 0)
            return cmp(v1, v2)
        addrs.sort(addr_cmp)
        for_keep_a_slot_addrs = addrs[:]
        
        fixer = MigrateSlotTaskFixer(64, cc)

        def new_task(t):
            if t:
                tasks.discard(t)
                tag = 'ok' if t.finished == 'ok' else 'fail'
                busy[level(t.src.addr)] -= 1
                busy[level(t.dst.addr)] -= 1
                slot_task = addr_slots[t.dst.addr][t.slot]
                slot_task['srcs'].remove(t.src.addr)
                if len(slot_task['srcs']) == 0:
                    addr_slots[t.dst.addr].pop(t.slot)
                    slot_finish[t.slot] = True
                    count[0] += 1
                tprint(tag, 'migrate slot %d from %s to %s finish, total tasks progress:%d/%d' % (t.slot, t.src.addr, t.dst.addr, count[0], total))
                if len(addr_slots[t.dst.addr]) == 0:
                    addr_slots.pop(t.dst.addr)
                    addrs.remove(t.dst.addr)
                if t.finished != 'ok':
                    slot_succ[t.slot] = False
                    fails.append((t.slot, 'from %s to %s exception:%s' % (t.src.addr, t.dst.addr, t.finished)))
                if slot_finish[t.slot] and slot_succ[t.slot]:
                    fixer.add(t)

                if t.taskid != taskid:
                    raise Exception('current taskid changed %s -> %s, abort migrate flow' % (taskid, t.taskid))

            all_addrs = for_keep_a_slot_addrs + addrs
            for addr in all_addrs:
                s = addr_slots[addr]
                if busy[level(addr)] > 0:
                    continue
                for slot, slot_task in s.iteritems():
                    if slot_task['mode'] == TaskMode.assign:
                        continue
                    for src in slot_task['srcs']:
                        if busy[level(src)] > 0:
                            continue
                        if len(tasks) >= max_parellel:
                            break
                        try:
                            for_keep_a_slot_addrs.remove(addr)
                        except:
                            pass
                        busy[level(addr)] += 1
                        busy[level(src)] += 1
                        t = MigrateSlotTask(self.nodes[addr][0], slot, self.nodes[src][0], self.client, taskid, slot_task['mode'], pipeline=pipeline, timeout=timeout)
                        tasks.add(t)
                        t.start(new_task)
                    if len(tasks) >= max_parellel:
                        break
                if len(tasks) >= max_parellel:
                    break

        try:
            new_task(None)
            self.poll.wait(timeout)
        except Exception as excp:
            traceback.print_exc()
            tprint('error', 'migrate task %s fail:%s' % (taskid, str(excp)))

        try:
            fixer.flush()
        except Exception as excp:
            traceback.print_exc()
            tprint('error', 'migrate task %s fail:%s' % (taskid, str(excp)))

        try:
            self.client.call('expire', redis_lock_key_migrate, 60)
        except:
            pass
        if len(fails) > 0:
            fails.sort(lambda x,y:x[0]-y[0])
            for i in fails:
                tprint('fail', 'slot %d fail:%s' % i)

    def call(self, *args, **kwargs):
        r = {}
        def cb(res, inst):
            r[inst.addr] = res
        for _, nodes in self.nodes.iteritems():
            inst = nodes[0]
            inst.async_call(functools.partial(cb, inst=inst), *args)
        timeout = kwargs.get('timeout', 60)
        self.poll.wait(timeout)
        return r

    def remove(self, addrs, timeout=60, mode='soft'):
        addrs = set(addrs)
        ids = set()

        def forget(res, inst, id, addr):
            tag = 'error' if isinstance(res, Exception) else 'ok'
            tprint(tag, '%s cluster forget %s(%s):%s' % (inst.addr, id, addr, str_or_repr(res)))

        for addr in addrs:
            nodes = self.nodes.get(addr, [])
            if not nodes:
                continue
            for n in nodes:
                if n.id:
                    ids.add((n.id, addr))

        for _, nodes in self.nodes.iteritems():
            inst = nodes[0]
            if inst.addr in addrs:
                continue
            for id in ids:
                inst.async_call(functools.partial(forget, inst=inst, id=id[0], addr=id[1]), 'cluster', 'forget', id[0])

        self.poll.wait(timeout)

        r = {}
        mode = 'hard' if mode.lower() == 'hard' else 'soft'

        def cb(res, inst):
            r[inst.addr] = res

        for addr in addrs:
            nodes = self.nodes.get(addr, [])
            if not nodes:
                continue
            inst = nodes[0]
            inst.async_call(functools.partial(cb, inst=inst), 'cluster', 'reset', mode)

        self.poll.wait(timeout)

        return r

def cluster_init_cmd(args):
    shards = []
    addrs = []
    for s in args.shard:
        shard = s.split(',')
        if len(shard) == 0:
            raise ValueError, 'invalid shard:%s' % s
        shards.append(shard)
        addrs += shard
    cc = ClusterController()
    cc.set_by_addrs(addrs, password=args.password)
    state, msgs = cc.init(shards)
    tprint('cluster_init finish:%s' % str(state))
    for i in msgs:
        tprint(i[0], i[1])

def get_args_addrs(args):
    addrs = []
    for i in args.addr:
        addrs += i.split(',')
    return addrs

def cluster_info_cmd(args):
    addrs = get_args_addrs(args)
    cc = ClusterController()
    cc.set_by_addrs(addrs, timeout=args.timeout, password=args.password)
    m = cc.info(timeout=args.timeout)

    for v, insts in m.get('Exception', {}).iteritems():
        tprint('error', '%s %s' % (v, repr([i.addr for i in insts])))

    keys = ['cluster_state', 'cluster_slots_assigned', 'cluster_slots_ok', 'cluster_slots_pfail', 'cluster_slots_fail', 'cluster_known_nodes', 'cluster_size', 'cluster_current_epoch']
    for k in keys:
        vals = m[k]
        if len(vals) == 1:
            tprint('%s:%s' % (k, vals.keys()[0]))
        else:
            for v, insts in vals.iteritems():
                tprint('error', '%s:%s %s' % (k, v, ','.join([i.addr for i in insts])))

    keys = ['cluster_my_epoch']
    for k in keys:
        vals = m[k]
        for v, insts in vals.iteritems():
            tprint('%s:%s %s' % (k, v, ','.join([i.addr for i in insts])))

def cluster_view_cmd(args):
    addrs = get_args_addrs(args)
    cc = ClusterController()
    cc.set_by_addrs(addrs, timeout=args.timeout, password=args.password)
    view = cc.view()
    insts = view['insts']
    slots = view['slots']
    unstable_slots = view['unstable_slots']
    excp_insts = view['excp_insts']
    if len(excp_insts) > 0:
        tprint('-------------------- exception nodes -----------------------------')
        for i in excp_insts:
            tprint('warn', '%s msgs:%s' % (i.addr, i.msgs))
    nodes = []
    for addr, views in insts.iteritems():
        for v in views:
            nodes.append(v[0])
    def cmp(i1, i2):
        k1 = '%s_%s_m_%s' % (str(i1.addr), str(i1.id), str(i1.addr))
        k2 = '%s_%s_m_%s' % (str(i2.addr), str(i2.id), str(i2.addr))
        if i1.role == 'slave':
            master = i1.master.addr if i1.master else 'None'
            k1 = '%s_%s_s_%s' % (master, str(i1.masterid), str(i1.addr))
        if i2.role == 'slave':
            master = i2.master.addr if i2.master else 'None'
            k2 = '%s_%s_s_%s' % (master, str(i2.masterid), str(i2.addr))
        if k1 < k2:
            return -1
        elif k1 > k2:
            return 1
        return 0
    nodes.sort(cmp)
    tprint('-------------------- nodes -----------------------------')
    instTags = {}
    master = None
    for i in nodes:
        tag = ''
        src = ''
        if len(insts[i.addr]) == 1:
            tag = 'ok' if i.id else 'error'
            if i.flags:
                if i.flags.find('fail?') >= 0:
                    tag = 'pfail'
                elif i.flags.find('fail') >= 0:
                    tag = 'fail'
        else:
            tag = 'conflict'
            src = ' ' + i.src
        instTags[i.addr] = tag
        if i.role == 'master':
            tprint(tag, '%s %-21s %-20s %s %d%s' % (i.id, i.addr, i.flags, i.masterid, len(i.slots), src))
            master = i
        else:
            if master and i.masterid == master.id:
                mid = master.addr
            else:
                mid = i.masterid
            tprint(tag, '%s %-21s %-20s %s%s' % (i.id, i.addr, i.flags, mid, src))
    tprint('-------------------- slots -----------------------------')
    slots = slot_array_merge(slots)
    for s in slots:
        slot = str(s[0]) if len(s) == 2 else '%d-%d'%(s[0], s[1])
        if s[-1] == None:
            tprint('unassign', '%-12s %-21s' % (slot, 'none'))
        elif len(s[-1]) == 1:
            addr = s[-1].keys()[0]
            instTag = instTags.get(addr, 'error')
            if instTag == 'conflict':
                instTag = 'ok'
            tprint(instTag, '%-12s %-21s' % (slot, addr))
        else:
            for k, v in s[-1].iteritems():
                tprint('conflict', '%-12s %-21s %s' % (slot, k, ','.join(v)))
    if len(unstable_slots):
        tprint('-------------------- unstable slots -----------------------------')
        slots = unstable_slots.keys()
        slots.sort()
        for s in slots:
            for m in ['importing', 'migrating']:
                for i in unstable_slots[s][m]:
                    arrow = '<' if m == 'importing' else '>'
                    tprint('warn', '%s %d %s -%s- %-21s(%s)' % (m, s, i[0], arrow, i[1], i[2]))

def get_addr_slots(args):
    addr_slots = {}
    for i in args.addr_slots:
        e = i.split(',')
        if len(e) < 2:
            raise Exception('invalid addr_slots argument:%s' % i)
        addr = e[0]
        slots = []
        for j in e[1:]:
            begin = end = -1
            s = j.split('-')
            if len(s) == 1:
                begin = int(s[0])
                end = begin + 1
            elif len(s) == 2:
                begin = int(s[0])
                end = int(s[1]) + 1
            if begin < 0 or end > 16384 or begin >= end:
                raise Exception('invalid slot specify argument:%s' % i)
            slots += xrange(begin, end)
        if addr in addr_slots:
            slots += addr_slots[addr]
        slots = list(set(slots))
        slots.sort()
        addr_slots[addr] = slots
    return addr_slots

def cluster_reshard_cmd(args):
    addr_slots = get_addr_slots(args)
    cc = ClusterController()
    cc.set_by_addrs(addr_slots.keys(), timeout=args.timeout, password=args.password)
    r = cc.prepare_migrate_slots(addr_slots, fix=args.fix, force_lock=args.force_lock)
    if not r['state']:
        tprint('error', 'reshard prepare migrate slots error')
        for i in r.get('msgs', []):
            tprint(i[0], i[1])
        return 'error'
    for i in r.get('msgs', []):
        tprint(i[0], i[1])
    if len(r['addr_slots']) == 0:
        tprint('ok', 'no slot need migrate')
        return
    cc.migrate_slots(r['addr_slots'], r['taskid'],
                     parellel_level=args.parellel_level,
                     max_parellel=args.max_parellel,
                     pipeline=args.pipeline,
                     timeout=args.timeout)

def call_output(r, groupby):
    if groupby == 'result':
        m = {}
        for addr, res in r.iteritems():
            k = str_or_repr(res)
            if k in m:
                m[k].append(addr)
            else:
                m[k] = [addr]
        for k, addrs in m.iteritems():
            addrs.sort()
            tprint('%s %s' % (k, ','.join(addrs)))
    else:
        for addr, res in r.iteritems():
            tprint('%-16s %s' % (addr, str_or_repr(res)))

def call_cmd(args):
    addrs = get_args_addrs(args)
    ic = InstsController(addrs, password=args.password)
    r = ic.call(*args.command, timeout=args.timeout)
    call_output(r, args.groupby)

def cluster_call_cmd(args):
    addrs = get_args_addrs(args)
    cc = ClusterController()
    cc.set_by_addrs(addrs, timeout=args.timeout, password=args.password)
    r = cc.call(*args.command, timeout=args.timeout)
    call_output(r, args.groupby)

def cluster_remove_cmd(args):
    addrs = get_args_addrs(args) if args.addr else []
    deletes = []
    for i in args.delete:
        deletes += i.split(',')
    cc = ClusterController()
    cc.set_by_addrs(addrs + deletes, timeout=args.timeout, password=args.password)
    r = cc.remove(deletes, timeout=args.timeout, mode=args.mode)
    for addr, res in r.iteritems():
        tag = 'error' if isinstance(res, Exception) else 'ok'
        tprint(tag, '%s cluster reset %s:%s' % (addr, args.mode, str_or_repr(res)))

cmdfunc = {
    'call': call_cmd,
    'cluster_init': cluster_init_cmd,
    'cluster_info': cluster_info_cmd,
    'cluster_view': cluster_view_cmd,
    'cluster_reshard': cluster_reshard_cmd,
    'cluster_call': cluster_call_cmd,
    'cluster_remove': cluster_remove_cmd,
}

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(help='command help', dest='cmd')

    call_parser = subparsers.add_parser('call', help='call command for multi instances')
    call_parser.add_argument('--groupby', default='inst', choices=['result', 'inst'], help='output groupby, default:inst')
    call_parser.add_argument('-i', '--addr', nargs='+', required=True, help='specify redis instance address, format: ip:port[,ip:port...]')
    call_parser.add_argument('-c', '--command', nargs='+', required=True, help='specify redis command')
    call_parser.add_argument('--timeout', type=int, default=60, help='timeout seconds, default:60')
    call_parser.add_argument('--password', default=None, help='redis auth password')

    cluster_init_parser = subparsers.add_parser('cluster_init', help='init cluster instances')
    cluster_init_parser.add_argument('shard', nargs='+', help='specify redis instance shard, format: ip:port,... eg: 10.2.3.4:6379,10.2.3.5:6379')
    cluster_init_parser.add_argument('--password', default=None, help='redis auth password')

    cluster_info_parser = subparsers.add_parser('cluster_info', help='show cluster info')
    cluster_info_parser.add_argument('addr', nargs='+', help='specify redis instance address, format: ip:port')
    cluster_info_parser.add_argument('--timeout', type=int, default=60, help='timeout seconds, default:60')
    cluster_info_parser.add_argument('--password', default=None, help='redis auth password')

    cluster_view_parser = subparsers.add_parser('cluster_view', help='show cluster nodes and slots')
    cluster_view_parser.add_argument('addr', nargs='+', help='specify redis instance address, format: ip:port')
    cluster_view_parser.add_argument('--timeout', type=int, default=60, help='timeout seconds, default:60')
    cluster_view_parser.add_argument('--password', default=None, help='redis auth password')

    cluster_reshard_parser = subparsers.add_parser('cluster_reshard', help='migrate slots')
    cluster_reshard_parser.add_argument('--parellel-level', default='host', choices=['host', 'inst'], help='parellel level, default:host')
    cluster_reshard_parser.add_argument('--max-parellel', type=int, default=1, help='max parellel, default:1')
    cluster_reshard_parser.add_argument('--pipeline', type=int, default=10, help='pipeline keys for each migrate command, default:10')
    cluster_reshard_parser.add_argument('--timeout', type=int, default=100, help='migrate command timeout seconds, default:100')
    cluster_reshard_parser.add_argument('--fix', action='store_true', help='fix abnormal slots')
    cluster_reshard_parser.add_argument('--force-lock', action='store_true', help='force get migrate lock')
    cluster_reshard_parser.add_argument('addr_slots', nargs='+', help='specify destination redis address and slots, format: host:port,slot,slot..., eg: 10.2.2.2:7638,0,2,3,10-20')
    cluster_reshard_parser.add_argument('--password', default=None, help='redis auth password')

    cluster_call_parser = subparsers.add_parser('cluster_call', help='call command for all cluster instances')
    cluster_call_parser.add_argument('--groupby', default='inst', choices=['result', 'inst'], help='output groupby, default:inst')
    cluster_call_parser.add_argument('-i', '--addr', nargs='+', required=True, help='specify redis instance address, format: ip:port[,ip:port...]')
    cluster_call_parser.add_argument('-c', '--command', nargs='+', required=True, help='specify redis command')
    cluster_call_parser.add_argument('--timeout', type=int, default=60, help='timeout seconds, default:60')
    cluster_call_parser.add_argument('--password', default=None, help='redis auth password')

    cluster_remove_parser = subparsers.add_parser('cluster_remove', help='remove some instances from cluster')
    cluster_remove_parser.add_argument('-i', '--addr', nargs='*', help='specify redis instance address, format: ip:port[,ip:port...]')
    cluster_remove_parser.add_argument('-d', '--delete', nargs='+', required=True, help='specify redis instance address to delete, format: ip:port[,ip:port...]')
    cluster_remove_parser.add_argument('--timeout', type=int, default=60, help='timeout seconds, default:60')
    cluster_remove_parser.add_argument('--mode', default='soft', choices=['hard', 'soft'], help='cluster reset mode, default:soft')
    cluster_remove_parser.add_argument('--password', default=None, help='redis auth password')

    args = parser.parse_args()
    try:
        r = cmdfunc[args.cmd](args)
        if r != None:
            sys.exit(1)
    except:
        traceback.print_exc()
        sys.exit(1)
