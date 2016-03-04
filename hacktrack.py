#!/usr/bin/python2

######################################################################
#    __  __           __  ______                __  
#   / / / /___ ______/ /_/_  __/________ ______/ /__
#  / /_/ / __ `/ ___/ //_// / / ___/ __ `/ ___/ //_/
# / __  / /_/ / /__/ ,<  / / / /  / /_/ / /__/ ,<   
#/_/ /_/\__,_/\___/_/|_|/_/ /_/   \__,_/\___/_/|_|
#
######################################################################
#HackTrack | A tool to correlate and normalize data found within the 
#            raw output of tools used during a pentesting engagement.


#Copyright (C) 2015  Kory Findley

#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.

#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.

#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <http://www.gnu.org/licenses/>.
######################################################################

import sys
import os
import glob
import json
import blessings
import random
import readline
import subprocess
import re

from htmodules import htconfig
from htmodules import htparser
from argparse import ArgumentParser
from datetime import date
from netaddr import *



def loadRaw(file):
    with open(file,'r') as loadfile:
        return loadfile.read().strip()

def newKeys():
    keys = {'hacktrack':{'hosts':{},'credentials':{},'stolen':{}}}
    return keys

def jsonWriter(jdata,jfile):
    with open(jfile, 'w') as sfile:
        json.dump(jdata, sfile)
    return

def jsonLoader(jfile):
    with open(jfile, 'r') as jdata:
        sdata = json.load(jdata)
        return sdata

def createSession(sfile):
    skeys = newKeys()
    jsonWriter(skeys, sfile)
    return "[<>] Session created."

def sessionHandler(file):
    checkfile = glob.glob(file)
    if len(checkfile) == 0:
        print "[--] Session does not exist."
        print createSession(file)
        print "[<>] Using session file: {}".format(file)
        loadkeys = jsonLoader(file)
        return loadkeys

    elif len(checkfile) == 1:
        print "[<>] Using session file: {}".format(file)
        loadkeys = jsonLoader(file)
        return loadkeys

    else:
        return "[--] Could not load session."

def sortIPS(iplist):
    return sorted(iplist, key=lambda ip: long(''.join(["%02X" % long(i) for i in ip.split('.')]), 16))

def sortPorts(portlist):
    return map(str,sorted(map(int,portlist)))


def checkLen(c):
    return len(c)

def checkBase(b):
    basecmds = htconfig.HT_CMDS.keys()
    if b in basecmds:
        return 0
    else:
        return 1

def checkSub(b,s):
    subcmds = htconfig.HT_CMDS[b]
    if s in subcmds:
        return 0
    else:
        return 1

def htCmdList():
    cmds = htconfig.HT_CMDS
    return cmds

def htHelp(type=None):
    fetchcmds = htCmdList()
    base_cmds = fetchcmds.keys()
    if type:
        for base in base_cmds:
            if base == type:
                print base,fetchcmds[base]
            else:
                continue
    else:
        print base_cmds

def formatHosts(hlist):
    host_str = ''.join(hlist)
    if '/' in host_str:
        ip_range_list = IPNetwork(host_str).iter_hosts()
        return map(str,ip_range_list)

    elif '-' in host_str:
        iplist = []
        split = ''.join(host_str).split('-')
        start = split[0]
        end = '{}.{}'.format('.'.join(start.split('.')[0:3]),split[1])
        range = IPRange(start,end)
        for ip in range:
            iplist.append(str(ip))
        return iplist

    elif ',' in host_str:
        iplist = []
        start = ''.join(host_str).split(',')
        iplist.append(start[0])
        tri_oct = '.'.join(start[0].split('.')[0:3])
        single_oct = start[1:]

        for oct in single_oct:
            addr = '{}.{}'.format(tri_oct,oct)
            iplist.append(addr)
        return iplist

    else:
        return hlist

def formatPorts(flist):
    portstr = ''.join(flist)
    if ',' in portstr:
        portlist = portstr.split(',')
        return portlist
    elif '-' in portstr:
        portlist = portstr.split('-')
        if len(portlist) == 2:
            convert = map(int,portlist)
            portrange = range(convert[0],convert[1])
            return portrange
        else:
            convert = map(int,portlist)
            portrange = range(convert[0],convert.pop())
            return portrange
    
    else:
        return flist

def formatServices(slist):
    servicestr = ''.join(slist)
    if ',' in servicestr:
        servicelist = servicestr.split(',')
        return servicelist
    else:
        return slist

def uniqListCount(ulist):
    return len(list(set(ulist)))

def hostSummary(keys,hosts=None):
    if hosts:
        hosts = formatHosts(hosts)
    else:
        hosts = keys['hacktrack']['hosts'].keys()
    width = blessings.Terminal().width
    border = '=' * width
    root_key_select = keys['hacktrack']
    host_key_select = root_key_select['hosts']
    title = '\033[1;32m{0:16}\033[1;m | {1:6} | {2:10} | {3:15} | {4:55} | {5:30}'.format('Hosts','Ports','Protocols','Services','Fingerprints','Platforms')
    print border
    print title
    print border
    for addr in sortIPS(hosts):
        if addr in host_key_select:
            ports = host_key_select[addr]['ports'].keys()
            platform = host_key_select[addr]['os']['platform']
            for port in sortPorts(ports):
                port_key_select = host_key_select[addr]['ports'][port]
                fprint = port_key_select['application']
                service = port_key_select['service']
                protocol = port_key_select['protocol']
                print '\033[1;32m{0:16}\033[1;m | {1:6} | {2:10} | {3:15} | {4:55} | {5:30}'.format(addr,port,protocol,service,' '.join(fprint),platform)
        else:
            continue
    print border               

def portSummary(keys,portlist=None):
    root_key_select = keys['hacktrack']
    host_key_select = root_key_select['hosts']

    width = blessings.Terminal().width
    border = '=' * width
    title = '{0:16} | \033[1;32m{1:6}\033[1;m | {2:10} | {3:15} | {4:55} | {5:30}'.format('Hosts','Ports','Protocols','Services','Fingerprints','Platforms')
    print border
    print title
    print border
    for addr in sortIPS(host_key_select.keys()):
        if portlist:
            ports = formatPorts(portlist)
        else:
            ports = host_key_select[addr]['ports'].keys()
        platform = host_key_select[addr]['os']['platform']
        for port in sortPorts(ports):
            if port in host_key_select[addr]['ports'].keys():
                port_key_select = host_key_select[addr]['ports'][port]
                fprint = port_key_select['application']
                service = port_key_select['service']
                protocol = port_key_select['protocol']
                print '{0:16} | \033[1;32m{1:6}\033[1;m | {2:10} | {3:15} | {4:55} | {5:30}'.format(addr,port,protocol,service,' '.join(fprint),platform)
            else:
                continue
    print border

def serviceSummary(keys,servicelist=None):
    root_key_select = keys['hacktrack']
    host_key_select = root_key_select['hosts']

    width = blessings.Terminal().width
    border = '=' * width
    title = '{0:16} | {1:6} | {2:10} | \033[1;32m{3:15}\033[1;m | {4:55} | {5:30}'.format('Hosts','Ports','Protocols','Services','Fingerprints','Platforms')
    print border
    print title
    print border
    for addr in sortIPS(host_key_select.keys()):
        ports = host_key_select[addr]['ports'].keys()
        platform = host_key_select[addr]['os']['platform']
        for port in sortPorts(ports):
            service = host_key_select[addr]['ports'][port]['service']
            fprint = host_key_select[addr]['ports'][port]['application']
            protocol = host_key_select[addr]['ports'][port]['protocol']
            if servicelist:
                for serv in sorted(formatServices(servicelist)):
                    if serv == service:
                        print '{0:16} | {1:6} | {2:10} | \033[1;32m{3:15}\033[1;m | {4:55} | {5:30}'.format(addr,port,protocol,service,' '.join(fprint),platform)
                    else:
                        continue
            else:
                print '{0:16} | {1:6} | {2:10} | \033[1;32m{3:15}\033[1;m | {4:55} | {5:30}'.format(addr,port,protocol,service,' '.join(fprint),platform)

    print border

def fingerprintSummary(keys,fprintfilter=None):
    root_key_select = keys['hacktrack']
    host_key_select = root_key_select['hosts']

    width = blessings.Terminal().width
    border = '=' * width
    title = '{0:16} | {1:6} | {2:10} | {3:15} | \033[1;32m{4:55}\033[1;m | {5:30}'.format('Hosts','Ports','Protocols','Services','Fingerprints','Platforms')
    print border
    print title
    print border
    for addr in sortIPS(host_key_select.keys()):
        ports = host_key_select[addr]['ports'].keys()
        platform = host_key_select[addr]['os']['platform']
        for port in sortPorts(ports):
            service = host_key_select[addr]['ports'][port]['service']
            fprint = host_key_select[addr]['ports'][port]['application']
            protocol = host_key_select[addr]['ports'][port]['protocol']
            if fprintfilter:
                if fprintfilter in ' '.join(fprint).upper() or fprintfilter in ' '.join(fprint).lower() or fprintfilter in ' '.join(fprint).capitalize():
                    print '{0:16} | {1:6} | {2:10} | {3:15} | \033[1;32m{4:55}\033[1;m | {5:30}'.format(addr,port,protocol,service,' '.join(fprint),platform)
                else:
                    continue
            else:
                print '{0:16} | {1:6} | {2:10} | {3:15} | \033[1;32m{4:55}\033[1;m | {5:30}'.format(addr,port,protocol,service,' '.join(fprint),platform)

    print border

def platformSummary(keys,platformfilter=None):
    root_key_select = keys['hacktrack']
    host_key_select = root_key_select['hosts']

    width = blessings.Terminal().width
    border = '=' * width
    title = '{0:16} | {1:6} | {2:10} | {3:15} | {4:55} | \033[1;32m{5:30}\033[1;m'.format('Hosts','Ports','Protocols','Services','Fingerprints','Platforms')
    print border
    print title
    print border
    for addr in sortIPS(host_key_select.keys()):
        ports = host_key_select[addr]['ports'].keys()
        platform = host_key_select[addr]['os']['platform']
        for port in sortPorts(ports):
            service = host_key_select[addr]['ports'][port]['service']
            fprint = host_key_select[addr]['ports'][port]['application']
            protocol = host_key_select[addr]['ports'][port]['protocol']
            if platformfilter:
                if platformfilter in platform.upper() or platformfilter in platform.lower() or platformfilter in platform.capitalize():
                    print '{0:16} | {1:6} | {2:10} | {3:15} | {4:55} | \033[1;32m{5:30}\033[1;m'.format(addr,port,protocol,service,' '.join(fprint),platform)
                else:
                    continue
            else:
                print '{0:16} | {1:6} | {2:10} | {3:15} | {4:55} | \033[1;32m{5:30}\033[1;m'.format(addr,port,protocol,service,' '.join(fprint),platform)

    print border

def htExec(pcmd,sfile,skeys):
    print ''

    if pcmd[0] == 'help':
        if len(pcmd) == 1:
            htHelp()
        elif len(pcmd) == 2:
            htHelp(type=pcmd[1])
        else:
            pass

    elif pcmd[0] == 'load':
        if len(pcmd) == 1:
            print htHelp(type='load')

        elif len(pcmd) == 2:
            if pcmd[1] in glob.glob(pcmd[1]):
                loadkeys = htparser.loadRawData(pcmd[1],skeys)
                jsonWriter(loadkeys,sfile)
            else:
                print "[--] File not found."
        else:
            pass

    elif pcmd[0] == 'hosts':
        if len(pcmd) == 1:
            hostSummary(skeys)
        elif len(pcmd) == 2:
            hostSummary(skeys,hosts=[pcmd[1]])
        else:
            pass

    elif pcmd[0] == 'ports':
        if len(pcmd) == 1:
            portSummary(skeys)
        elif len(pcmd) == 2:
            portSummary(skeys,portlist=[pcmd[1]])
        else:
            pass

    elif pcmd[0] == 'services':
        if len(pcmd) == 1:
            serviceSummary(skeys)
        elif len(pcmd) == 2:
            serviceSummary(skeys,servicelist=[pcmd[1]])
        else:
            pass

    elif pcmd[0] == 'fprints':
        if len(pcmd) == 1:
            fingerprintSummary(skeys)
        elif len(pcmd) == 2:
            fingerprintSummary(skeys,fprintfilter=pcmd[1])
        else:
            pass

    elif pcmd[0] == 'platforms':
        if len(pcmd) == 1:
            platformSummary(skeys)
        elif len(pcmd) == 2:
            platformSummary(skeys,platformfilter=pcmd[1])
        else:
            pass

def htShell(session_file,session_keys):
    status = 0
    prompt = '[hacktrack]-> '
    while status == 0:
        cmd = raw_input(prompt).strip().split()
        if cmd[0] == 'exit':
            status = 1
        else:
            htExec(cmd,session_file,session_keys)

def banner():
    os.system('clear')
    banners = glob.glob('{}htbanners/*'.format(htconfig.HT_PATH))
    with open(random.choice(banners),'r') as banner:
        print banner.read()

def checkReqPaths():
    hacktrack_path = htconfig.HT_PATH
    if os.path.isdir('{}.htsessions'.format(hacktrack_path)) == False:
        print "[--] Sessions path not found."
        os.system('mkdir {}.htsessions'.format(hacktrack_path))
        print "[<>] Sessions path created."

    if os.path.isdir('{}.htreports'.format(hacktrack_path)) == False:
        print "[--] Reports path not found."
        os.system('mkdir {}.htreports'.format(hacktrack_path))
        print "[<>] Reports path created."

def indexSessions():
    sessions = glob.glob('{}.htsessions/*'.format(htconfig.HT_PATH))
    if len(sessions) != 0:
        sessionlist = '{}\nSaved Sessions\n{}\n{}\n{}'.format('='*60,'='*60,'\n'.join([s.split('/').pop().strip() for s in sessions]),'='*60)
        return sessionlist
    else:
        return '{}\nSaved Sessions\n{}\n{}\n{}'.format('='*60,'='*60,'[--] No saved sessions available','='*60)


def main():
    banner()
    hacktrack_path = htconfig.HT_PATH
    parser = ArgumentParser(description='HackTrack | A tool to correlate and normalize data found within the raw output of tools used during a pentest engagement.')

    parser.add_argument('-s', '--session', help='name of HackTrack session to use')

    args = parser.parse_args()
    session = args.session

    checkReqPaths()

    if session:
        sessionkeys = sessionHandler('{}.htsessions/{}'.format(hacktrack_path,session))
        htShell('{}.htsessions/{}'.format(hacktrack_path,session),sessionkeys)
    else:
        session = 'hacktrack_session_{}'.format(date.today())
        sessionkeys = sessionHandler('{}.htsessions/{}'.format(hacktrack_path,session))
        htShell('{}.htsessions/{}'.format(hacktrack_path,session),sessionkeys)


main()
