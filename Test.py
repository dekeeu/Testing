from httplib import *
from urlparse import *

import argparse

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
        
    class ScanException:
        def __init__(self, message):
            self._message = message
            
        def getMessage(self):
            return self._message
# Main class

class Testing:
    def __init__(self, domain, new):
        self._httpPort = 80
        self._httpsPort = 443
        
        self._unsecureScheme = 'http://'
        self._secureScheme = 'https://'
        
        self._defaultPath = '/'
        self._domain = domain
        
        self._sslLabsApiUrl = 'https://api.ssllabs.com/api/v2/'
        
        self._new = new
        
    def start(self):
        try:
            self.checkArguments()
            self.checkUP()
            self.checkRedirect()
            self.checkCertificate()
            #self.openPorts()
        except CustomEx.HostDownException as e:
            print(e.getMessage())
        except socket.gaierror as e:
            print(e)
        except CustomEx.ScanException as e:
            print(e.getMessage())
            
    def checkArguments(self):
        if '-n' in sys.argv:
            self._new = True
            
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
        
        if len(_conn.history) == 0:
        #if _conn.is_redirect == False:
        #if _conn.history[0].status_code not in [300, 301, 302, 303, 304, 305, 306, 307, 308]:
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
        
        return {'done':_isDone, 'result':_result}
    
    def do_every(self):
        print('Current status: ' + bcolors.WARNING + 'In progress' + bcolors.ENDC)
        check = self.checkCertStatus()
        
        while check['done'] == False:
            time.sleep(5)
            check = self.checkCertStatus()
            print('Current status: ' + bcolors.WARNING + 'In progress' + bcolors.ENDC)
        
        print('Current status:' + bcolors.OKBLUE + ' Done' + bcolors.ENDC)
        return check['result']
     
    def checkCertificate(self):
        print('----- SSL/TLS Checking ----- ')
        
        if self._new:
            self.launchCertScan()
        _scanResult = self.do_every()
        
        _statusList = {0 : bcolors.WARNING + 'NOT checked' + bcolors.ENDC,
                           1 : bcolors.FAIL + 'certificate revoked' + bcolors.ENDC,
                           2 : bcolors.OKGREEN + 'certificate NOT revoked' + bcolors.ENDC,
                           3 : bcolors.WARNING + 'revocation check error' + bcolors.ENDC,
                           4 : bcolors.WARNING + 'no revocation information' + bcolors.ENDC,
                           5 : bcolors.WARNING + 'internal error' + bcolors.ENDC}
        
        _grades = {'A' : bcolors.OKGREEN + 'A' + bcolors.ENDC,
                   'A+' : bcolors.OKGREEN + 'A' + bcolors.ENDC,
                   'B' : bcolors.WARNING + 'B' + bcolors.ENDC,
                   'C' : bcolors.FAIL + 'C' + bcolors.ENDC,
                   'D' : bcolors.FAIL + 'D' + bcolors.ENDC,
                   'E' : bcolors.FAIL + 'E' + bcolors.ENDC,
                   'F' : bcolors.FAIL + 'F' + bcolors.ENDC}
        
        for endPoint in _scanResult['endpoints']:
            
            _certInfo = endPoint['details']['cert']
            _endpointInfo = endPoint['details']
            
            print('\nGrade: ' + _grades[endPoint['grade']] + '\n')
            
            """ Web server details """
            
            print(bcolors.HEADER + 'Web server information' + bcolors.ENDC)
            
            print('IP Address:' + endPoint['ipAddress'])
            
            
            """ Certificate Information """
            
            print(bcolors.HEADER + 'Certificate information' + bcolors.ENDC)
            
            print('Common Names: ' + ','.join(_certInfo['commonNames']))
            print('Alt Names: ' + ','.join(_certInfo['altNames']))
            print('Issuer info: ' + _certInfo['issuerLabel'] + '(' + _certInfo['issuerSubject'] + ')')
            print('SHA1 Thumbprint: ' + _certInfo['sha1Hash'])
            print('Signature Algorithm: ' + _certInfo['sigAlg'])
            
            print '-'*30
            
    
            """ Certificate Revoked Status """
            
            print('Revocation status: ' + _statusList[_certInfo['revocationStatus']])
            print('CRL Revocation status: ' + _statusList[_certInfo['crlRevocationStatus']])
            print('OCSP Revocation status: ' + _statusList[_certInfo['ocspRevocationStatus']])
            
            
            """ SSL Certificate Expiration """
            
            if _certInfo['notBefore'] / 1000 <= int(time.time()) <= _certInfo['notAfter'] / 1000:
                print('Certificate is ' + bcolors.OKGREEN + 'VALID' + bcolors.ENDC)
            else:
                print('Certificate is ' + bcolors.FAIL + 'EXPIRED' + bcolors.ENDC)
                
                
            """ SSL Certificate Match Name """
            # http://stackoverflow.com/questions/35822002/url-common-name-matching-python
    
            if _scanResult.has_key('certHostnames') == False:
                print("Certificate Name " + bcolors.OKGREEN + "matches " + bcolors.ENDC + self._domain)
            else:
                print("Certificate Name does " + bcolors.FAIL + "NOT match " + bcolors.ENDC + self._domain)
                
                
            """ Heartbleed Vulnerability """
            
            print 'Server vulnerable to HeartBleed:',
            if _endpointInfo['heartbleed'] == True:
                print(bcolors.FAIL + str(_endpointInfo['heartbleed']) + bcolors.ENDC)
            else:
                print(bcolors.OKGREEN + str(_endpointInfo['heartbleed']) + bcolors.ENDC)
            
            
            """ Protocol Support """
            print(bcolors.HEADER + 'Supported protocols: ' + bcolors.ENDC)
            for proto in _endpointInfo['protocols']:
                print proto['name'] + ', ' + proto['version']
            
            
            """ Chiper Support """
            
            print(bcolors.HEADER + 'Supported chipers: ' + bcolors.ENDC)
            for chip in _endpointInfo['suites']['list']:
                print chip['name']
                
                
class GUI:
    def __init__(self):
        self._parser = argparse.ArgumentParser()
    
    def start(self):
        self._parser.add_argument('-d', nargs='*', help = 'Domains', required = True)
        self._parser.add_argument('-n', action='store_true', help = 'New scan', required = False)
        self._args = self._parser.parse_args()
        
        for host in self._args.d:
            H = Testing(host,self._args.n)
            H.start()
            
g = GUI()
g.start()
