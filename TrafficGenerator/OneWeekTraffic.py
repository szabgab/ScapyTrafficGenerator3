
import datetime
from subprocess import Popen, PIPE
import os
import time
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import gc
#import Framework
import socket


class cleanup_helper():
    def __init__(self):
        self.get_objects()
    def get_objects(self):
        self.Objects = gc.get_objects()
    def close_all_open_sockets(self):
        self.get_objects()
        for object in self.Objects:
            if isinstance(object,socket.socket):
                object.close()



from support.HTTP_Support import *

def Get_Current_time():
    o = Popen('date "+%Y-%m-%d %H:%M:%S"', executable='/bin/bash', stdout=PIPE, shell=True)
    Lines = []
    for line in o.stdout.readlines():
        Lines.append(line.strip('\n').strip())
    nowtime = datetime.datetime.strptime(Lines[0].strip(), '%Y-%m-%d %H:%M:%S')
    return nowtime

def set_time(timeset):
    settimecommand = "date --set '%s'" % timeset
    print 'setting time with command', settimecommand
    o = Popen(settimecommand, executable='/bin/bash', stdout=PIPE, shell=True)



def set_time_to_past(days_ago=0,
                     hours_ago=0,
                     minutes_ago=0):
    nowtime = Get_Current_time()
    settime = (nowtime - datetime.timedelta(days=days_ago,
                                           hours=hours_ago,
                                           minutes=minutes_ago)).strftime("%Y-%m-%d %H:%M:%S")
    set_time(settime)

def set_time_to_future(days=0,
                     hours=0,
                     minutes=0,
                     seconds=0,
                     TIME=None):
    if not TIME:
        nowtime = Get_Current_time()
    else:
        nowtime = TIME
    settime = (nowtime + datetime.timedelta(days=days,
                                            hours=hours,
                                            minutes=minutes,
                                            seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S")
    set_time(settime)


def runTrafficTest(HTTP):
    HTTP.Packets = []
    HTTP.SetVariables(src=GenerateRandomIp(),
                      dst=GenerateRandomIp(),
                      sport=RandomSafePortGenerator(),
                      dport=RandomSafePortGenerator())
    HTTP.HTTP_TEST()
    sendp(HTTP.Packets, iface='eth2')

if __name__== '__main__':
    c = cleanup_helper()
    HTTP = HTTP_Support()
    # lets start by getting the most recent time
    Start= time.time()
    os.environ['EXTRA_FLOWS'] = '0'
    StartTime = Get_Current_time()

    #lets run begining traffic test
    runTrafficTest(HTTP)


    #run traffic for every hour of the week with 2 extra hours
    for i in range(0,180, 5):  #there are 168 hours in a week
        #run traffic
        set_time_to_past(hours_ago=5)
        #lets restart monit
        print 'stoping all services'
        Popen('monit restart all', executable='/bin/bash', stdout=PIPE, shell=True)
        print 'waiting 120s for all services to restart'
        sleep(120)
        print 'testing with date', Get_Current_time()
        #sleep(.1)
        for i in range(50):
            runTrafficTest(HTTP)
        sleep(.1)
        c.close_all_open_sockets()
        sleep(.1)


    #now lets set the time back
    End= time.time()
    set_time_to_future(seconds=int(End-Start),
                       TIME=StartTime)





