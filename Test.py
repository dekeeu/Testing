from httplib import *
from urlparse import *

import sys
import nmap
import socket
import requests
import json
import threading
import time
import re

# Colors for terminal : http://stackoverflow.com/questions/287871/print-in-terminal-with-colors-using-python

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
# Custom Exceptions

class CustomEx(Exception):
    class HostDownException:
        def __init__(self, message):
            self._message = message
        def getMessage(self):
            return self._message

    class RedirectException:
        def __init__(self, message):
            self._message = message
            
        def getMessage(self):
            return self._message
        
# Main class

class Testing:
    def __init__(self, domain):
        self._httpPort = 80
        self._httpsPort = 443
        
        self._unsecureScheme = 'http://'
        self._secureScheme = 'https://'
        
        self._defaultPath = '/'
        self._domain = domain
        
        self._sslLabsApiUrl = 'https://api.ssllabs.com/api/v2/'
        
    def start(self):
        try:
            self.checkUP()
            self.checkRedirect()
            self.checkCertificate()
            #self.openPorts()
        except CustomEx.HostDownException as e:
            print(e.getMessage())
        except socket.gaierror as e:
            print(e)
            
    def checkUP(self):
        _ports = [self._httpPort, self._httpsPort]
        _closedPorts = []
        _msg = ''
        
        print(bcolors.HEADER + '[ %s ] ' % self._domain + bcolors.ENDC)
        print('---- Checking if host is up -----')

        while True:
            for p in _ports:
                try:
                    socket.create_connection((self._domain, p), 5)
                except socket.timeout:
                    _closedPorts.append(p)
                    _ports.remove(p)
                except socket.gaierror as e:
                    raise e
                    
            break
        
        for closedPort in _closedPorts:
            _msg += bcolors.WARNING + 'Host does not respond on port ' + str(closedPort) + '\n' + bcolors.WARNING
            
        if len(_closedPorts) == 2:
            raise CustomEx.HostDownException(_msg)
        
        for p in _ports:
            print(bcolors.OKGREEN + 'Host is up on port ' + str(p) + bcolors.ENDC)   
            
    def openPorts(self):
        _nm = nmap.PortScanner()
        
        print('----- Checking for open ports -----')
        _nm.scan(hosts = self._domain, arguments ='-sV --open')
        
        for host in _nm.all_hosts():
            for _p in _nm[host].all_protocols():
                _ports = _nm[host][_p].keys()
                _ports.sort()
                
                if len(_ports) == 0:
                    print(bcolors.OKBLUE + 'No open ports.' + bcolors.ENDC)
                else:
                    for port in _ports:
                        if port not in [self._httpPort, self._httpsPort]:
                            print(bcolors.OKBLUE + 'Port : %s is %s' % (port, str(_nm[host][_p][port]['state']).upper()) + bcolors.ENDC)
            
    def checkRedirect(self):
        print('----- Checking redirect ----- ')
        
        _conn = requests.head(self._unsecureScheme + self._domain + self._defaultPath, allow_redirects = True)
        
        if _conn.history[0].status_code not in [300, 301, 302, 303, 304, 305, 306, 307, 308]:
            print(bcolors.FAIL + 'Site is still running on http://' + bcolors.ENDC)
            
        else:
            if _conn.url.find(self._unsecureScheme) == 0:
                print(bcolors.FAIL + 'Location header does not redirect to %s' % self._secureScheme + bcolors.ENDC)
            elif _conn.url.index(self._secureScheme) == 0:
                print(bcolors.OKGREEN + 'COOL ! %s redirects to %s' % (self._domain, self._secureScheme) + bcolors.ENDC)
            else:
                print(bcolors.UNDERLINE + 'Unknown scheme.' + bcolors.ENDC)

    def launchCertScan(self):
        _req = requests.get(self._sslLabsApiUrl + '/analyze?host=%s&publish=off&startNew=on&all=done' % self._domain)
    
    def checkCertStatus(self):
        _isDone = False
        _req = requests.get(self._sslLabsApiUrl + '/analyze?host=%s&all=done' % self._domain)
        
        _result = json.loads(_req.text)
        
        if _result['status'] == 'READY':
            _isDone = True
        
        return (_isDone,_result)
    
    def do_every(self, done):
        check = self.checkCertStatus()
        
        if done == False:
            print('Current status: ' + bcolors.WARNING + 'In progress' + bcolors.ENDC)
            done = check[0]
            threading.Timer(10, self.do_every,[done]).start()
        else:
            print('Current status:' + bcolors.OKBLUE + ' Done' + bcolors.ENDC)
            return check[1]
            
    def checkCertificate(self):
        print('----- SSL/TLS Checking ----- ')
        
        self.launchCertScan()
        _scanResult = self.do_every(False)
        
        _info = _scanResult['endpoints'][0]['details']['cert']
        _statusList = {0 : bcolors.WARNING + 'not checked' + bcolors.ENDC,
                       1 : bcolors.FAIL + 'certificate revoked' + bcolors.ENDC,
                       2 : bcolors.OKGREEN + 'certificate not revoked' + bcolors.ENDC,
                       3 : bcolors.WARNING + 'revocation check error' + bcolors.ENDC,
                       4 : bcolors.WARNING + 'no revocation information' + bcolors.ENDC,
                       5 : bcolors.WARNING + 'internal error' + bcolors.ENDC}
        
        
        # http://stackoverflow.com/questions/35822002/url-common-name-matching-python
        
        common_name = _info['cert']['commonNames']
        rxString = r'(?:^|\s)(\w+\.)?' + common_name.replace('.', '\.')[3:] + '(?:$|\s)'
        regex = re.compile(rxString)
        
        if regex.match(self._domain):
            print("Certificate Name " + bcolors.OKGREEN + " matches " + bcolors.ENDC + self._domain)
        else:
            print("Certificate Name does " + bcolors.FAIL + " NOT match " + bcolors.ENDC + self._domain)
        
        if _info['notBefore'] <= time.time() <= _info['notAfter']:
            print('\tCertificate is ' + bcolors.OKGREEN + 'VALID' + bcolors.ENDC)
        else:
            print('\tCertificate is ' + bcolors.FAIL + 'EXPIRED' + bcolors.ENDC)
            
        print('\tRevocation status: ' + _statusList[_info['revocationStatus']])
        print('\tCrl Revocation status' + _statusList[_info['crlRevocationStatus']])
        print('\tOCSP Revocation status ' + _statusList[_info['ocspRevocationStatus']])
        
        
        
        
    
for host in sys.argv[1:]:
    H = Testing(host)
    H.start()
