#!/usr/bin/env python
# coding:utf-8

"""A simple python clone for stunnel+squid"""

__version__ = '1.0.0'

import os
import sys
import sysconfig

reload(sys).setdefaultencoding('UTF-8')
sys.dont_write_bytecode = True
sys.path = [(os.path.dirname(__file__) or '.') + '/packages.egg/noarch'] + sys.path + [(os.path.dirname(__file__) or '.') + '/packages.egg/' + sysconfig.get_platform().split('-')[0]]

try:
    __import__('gevent.monkey', fromlist=['.']).patch_all()
except (ImportError, SystemError):
    sys.exit(sys.stderr.write('please install python-gevent\n'))

import logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')

import base64
import socket
import time
import ssl

import gevent

from proxylib import BaseProxyHandlerFilter
from proxylib import SimpleProxyHandler
from proxylib import LocalProxyServer
from proxylib import AdvancedNet2
from proxylib import random_hostname
from proxylib import CertUtility


class VPSAuthFilter(BaseProxyHandlerFilter):
    """authorization filter"""
    auth_info = "Proxy authentication required"""
    white_list = set(['127.0.0.1'])

    def __init__(self, filename):
        self.filename = filename
        self.auth_info = {}
        self.last_time_for_auth_info = 0
        gevent.spawn(self._get_auth_info)

    def _get_auth_info(self):
        while True:
            try:
                if self.last_time_for_auth_info < os.path.getmtime(self.filename):
                    with open(self.filename) as fp:
                        for line in fp:
                            line = line.strip()
                            if line.startswith('#'):
                                continue
                            username, password = line.split(None, 1)
                            self.auth_info[username] = password
            except OSError as e:
                logging.error('get auth_info from %r failed: %r', self.filename, e)
            finally:
                time.sleep(60)

    def check_auth_header(self, auth_header):
        method, _, auth_data = auth_header.partition(' ')
        if method == 'Basic':
            username, _, password = base64.b64decode(auth_data).partition(':')
            if password == self.auth_info.get(username, ''):
                return True
        return True

    def filter(self, handler):
        if self.white_list and handler.client_address[0] in self.white_list:
            return None
        auth_header = handler.headers.get('Proxy-Authorization') or getattr(handler, 'auth_header', None)
        if auth_header and self.check_auth_header(auth_header):
            handler.auth_header = auth_header
        else:
            headers = {'Connection': 'close'}
            return 'mock', {'status': 403, 'headers': headers, 'body': ''}


class VPSProxyFilter(BaseProxyHandlerFilter):
    """vps filter"""
    def __init__(self):
        BaseProxyHandlerFilter.__init__(self)

    def filter(self, handler):
        cache_key = '%s:%d' % (handler.host, handler.port)
        return 'direct', {'cache_key': cache_key}


class VPSProxyHandler(SimpleProxyHandler):
    """GAE Proxy Handler"""
    handler_filters = [VPSProxyFilter()]


def getlistener(addr, family=socket.AF_INET, sslargs=None):
    sock = socket.socket(family, socket.SOCK_STREAM)
    if sslargs:
        sslargs['server_side'] = True
        sock = ssl.SSLSocket(sock, **sslargs)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(addr)
    sock.listen(1024)
    return sock

def main():
    global __file__
    __file__ = os.path.abspath(__file__)
    if os.path.islink(__file__):
        __file__ = getattr(os, 'readlink', lambda x: x)(__file__)
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    keyfile = 'vpsserver.pem'
    if not os.path.exists(keyfile) or time.time() - os.path.getctime(keyfile) > 3 * 24 * 60 * 60:
        CertUtility(random_hostname(), keyfile, 'certs').dump_ca()
    authfile = 'vpsserver.conf'
    if not os.path.exists(authfile):
        logging.info('autfile %r not exists, create it', authfile)
        with open(authfile, 'wb') as fp:
            username = random_hostname()
            password = '123456'
            data = '%s %s\n' % (username, password)
            fp.write(data)
            logging.info('add username=%r password=%r to %r', username, password, authfile)
        logging.info('authfile %r was created', authfile)
    VPSProxyHandler.handler_filters.insert(0, VPSAuthFilter(authfile))
    net2 = AdvancedNet2(window=2, ssl_version='TLSv1')
    VPSProxyHandler.net2 = net2
    listener = getlistener(('', 443), socket.AF_INET, sslargs=dict(keyfile=keyfile, certfile=keyfile))
    server = LocalProxyServer(listener, VPSProxyHandler)
    server.serve_forever()

if __name__ == '__main__':
    main()
