#!/usr/bin/python

import sys
import os

def loadRaw(file):
    with open(file,'r') as loadfile:
        return loadfile.read().strip()

def loadRawData(file,keys):
    with open(file,'r') as loadfile:
        reader = loadfile.read()
        if 'Starting Nmap' and  '( https://nmap.org )' in reader:
            print '[<>] Nmap output detected.'
            nmapkeys = nmapFile(file,keys)
            print '[<>] Nmap file data loaded.'
            return nmapkeys

        elif '- Nikto v' in reader:
            print '[<>] Nikto output detected.'
            niktokeys = niktoFile(file,keys)
            print '[<>] Nikto file data loaded.'
            return niktokeys

        else:
            return "[--] File could not be parsed."

def niktoFile(file,keys):
    niktofile = loadRaw(file)
    loaddata = niktofile.split('\n\n')
    for data in loaddata:
        print data

def nmapFile(file,keys):
    nmapfile = loadRaw(file)
    loaddata = nmapfile.split('\n\n')
    for data in loaddata:
        parse = data.split('\n')
        for obj in parse:
            if obj == '':
                continue

            if obj.startswith('Starting Nmap'):
                continue

            if obj.startswith('SF:') or obj.startswith('SF-Port'):
                continue

            if obj.endswith('http://www.insecure.org/cgi-bin/servicefp-submit.cgi :'):
                continue

            if obj.startswith('Nmap scan report for'):
                host = obj.split().pop()
                keys['hacktrack']['hosts'].update({host:{'ports':{},'os':{}}})

            if obj.split()[1] == 'open':
                port = obj.split()[0].split('/')[0]
                proto = obj.split()[0].split('/')[1]
                service = obj.split()[2]
                if len(obj.split()) > 3:
                    application = obj.split()[3:]
                keys['hacktrack']['hosts'][host]['ports'].update({port:{'protocol':proto,'service':service,'application':application}})
    return keys
