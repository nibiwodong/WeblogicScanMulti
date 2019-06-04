#!/usr/bin/env python
# _*_ coding:utf-8 _*_

'''
 ____       _     _     _ _   __  __           _
|  _ \ __ _| |__ | |__ (_) |_|  \/  | __ _ ___| | __
| |_) / _` | '_ \| '_ \| | __| |\/| |/ _` / __| |/ /
|  _ < (_| | |_) | |_) | | |_| |  | | (_| \__ \   <
|_| \_\__,_|_.__/|_.__/|_|\__|_|  |_|\__,_|___/_|\_\

'''
import sys
from multiprocessing.dummy import Pool as ThreadPool

version = "1.2"
banner='''
__        __   _     _             _        ____                  
\ \      / /__| |__ | | ___   __ _(_) ___  / ___|  ___ __ _ _ __  
 \ \ /\ / / _ \ '_ \| |/ _ \ / _` | |/ __| \___ \ / __/ _` | '_ \ 
  \ V  V /  __/ |_) | | (_) | (_| | | (__   ___) | (_| (_| | | | |
   \_/\_/ \___|_.__/|_|\___/ \__, |_|\___| |____/ \___\__,_|_| |_|
                             |___/ 
                             By Tide_RabbitMask | V {} 
'''.format(version)


plugins = ['Console', 'CVE_2014_4210', 'CVE_2016_0638', 'CVE_2016_3510', 'CVE_2017_3248', 'CVE_2017_3506', 'CVE_2017_10271', 'CVE_2018_2628', 'CVE_2018_2893', 'CVE_2018_2894', 'CVE_2019_2725']
rip = sys.argv[1]
rport = int(sys.argv[2])
index = 0
def PocS(plugin):
    try:
        p = loadPlugin(plugin)
        p.run(rip, rport, index)
    except Exception as e:
        # print(e)
        print('[-]' + plugin + ' not detected.\n')


def loadPlugin(plugin):
    try:
        __import__("poc."+plugin)
        return sys.modules["poc."+plugin]
    except:
        return None

def run():
    print(banner)
    print('Welcome To WeblogicScan !!')
    if len(sys.argv)<3:
        print('Usage: python WeblogicScan [IP] [PORT]')
    else:
        pool = ThreadPool(10)
        results = pool.map(PocS, plugins)
        pool.close()
        pool.join()
    print ("[*]The mission is over,the goal is {}:{}".format(rip,rport))

if __name__ == '__main__':
    run()

