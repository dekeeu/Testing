#!/usr/bin/env python

import time
from pprint import pprint
from zapv2 import ZAPv2

class ZAPScan:
    def __init__(self, target):
        self._target = target
        
        self._httpProxy = 'http://127.0.0.1:1337'
        self._httpsProxy = 'http://127.0.0.1:1337'
        
        self._zap = ZAPv2(proxies = {'http':self._httpProxy, 'https':self._httpsProxy})
        self._apiKey = '5a8au7kjk7itl2flqkt4ufi19q'
        
    def start(self):
        """ Access the target """
        
        print("Opening target: " + self._target)
        self._zap.urlopen(self._target)
        time.sleep(2)
        
        self.spider()
        self.scan()
        self.report()
        
    def spider(self):
        """ Spider the target """
        
        print self._zap.httpsessions.activeS
        
        print('Spider the target')
        
        self._scanID = self._zap.spider.scan(self._target, apikey = self._apiKey)
        time.sleep(2)
        
        while int(self._zap.spider.status(self._scanID)) < 100:
            print('Spider progress %: ' + self._zap.spider.status(self._scanID))
            
        print('Spider completed')
        time.sleep(5)
        
    def scan(self):
        """ Scanning the target """
        
        print('Scan the target: ')
        
        self._scanID = self._zap.ascan.scan(self._target, apikey = self._apiKey)
        
        while int(self._zap.ascan.status(self._scanID)) < 100:
            print('Scan progress %: ' + self._zap.ascan.status(self._scanID))
            time.sleep(5)
        
        print('Scan completed')
        
    
    def report(self):
        """ Report the results """
        
        print('Hosts: ' + ', '.join(self._zap.core.hosts))
        print('Alerts: ')
        pprint(self._zap.core.alerts())
        
z = ZAPScan('https://dev2.iwelcome.com/login/')
z.start()
