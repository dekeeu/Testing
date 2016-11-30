from httplib import *
from urlparse import *

import sys
import nmap
import socket

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

class Testing:
    def __init__(self, domain):
        self._httpPort = 80
        self._httpsPort = 443
        
        self._unsecureScheme = 'http://'
        self._secureScheme = 'https://'
        self._domain = domain
        
    def start(self):
        try:
            self.checkUP()
            self.checkRedirect()
            self.openPorts()
        except CustomEx.HostDownException as e:
            print(e.getMessage())
        except socket.gaierror as e:
            print(e)
            
    def checkUP(self):
        _ports = [self._httpPort, self._httpsPort]
        _closedPorts = []
        _msg = ''
        
        print('[ %s ] ' % self._domain)
        print('---- Checking if host is up -----')

        while True:
            for p in _ports:
                try:
                    socket.create_connection((self._domain, p), 5)
                except:
                    _closedPorts.append(p)
                    _ports.remove(p)
            break
        
        for closedPort in _closedPorts:
            _msg += 'Host does not respond on port ' + str(closedPort) + '\n'
            
        if len(_closedPorts) == 2:
            raise CustomEx.HostDownException(_msg)
        
        for p in _ports:
            print('Host is up on port ' + str(p))   
            
    def openPorts(self):
        _nm = nmap.PortScanner()
        
        print('----- Checking for open ports -----')
        _nm.scan(hosts = self._domain, arguments ='-sV --open')
        
        for host in _nm.all_hosts():
            #print('Host: %s (%s)' % (host, _nm[host].hostname()))
            for _p in _nm[host].all_protocols():
                _ports = _nm[host][_p].keys()
                _ports.sort()
                
                for port in _ports:
                    if port not in [self._httpPort, self._httpsPort]:
                        print('Port : %s is %s' % (port, str(_nm[host][_p][port]['state']).upper()))
            
    def checkRedirect(self):
        print('----- Checking redirect ----- ')
        
        _connection = HTTPConnection(self._domain, self._httpPort)
        _connection.request('GET', '/')
        _response = _connection.getresponse()
        
        _responseHeaders = _response.getheaders()
        _locationHeader = _response.getheader('location', '')

        if  _locationHeader is '':
            print('Location header does not exist, site is still running on http://')
        
        else:
            _url = urlparse(_locationHeader)
            _urlScheme = _url.scheme
            
            if _urlScheme + '://' != self._secureScheme:
                print(str(_url))
                print('Location header does not redirect to %s' % self._secureScheme)
            else:
                print('COOL ! %s redirects to %s' % (self._domain, self._secureScheme))

    def checkCertificate(self):
        pass
    
for host in sys.argv[1:]:
    H = Testing(host)
    H.start()
