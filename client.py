#!/usr/bin/python

import sys
import pickle
import csv
import time

flow_match = ['in_port', 'dl_src', 'dl_dst', 'dl_type',
              'dl_vlan', 'nw_proto', 'nw_src', 'nw_dst',
              'nw_tos', 'tp_src', 'tp_dst']

import jsonrpclib
server = jsonrpclib.Server('http://localhost:8080')


def construct_hashed_sflow(match):
    """
    :params: OpenFlow match object
    :return: hashed value computed on that object
    """
    # Constructing key
    key = (match['in_port'],
           match['dl_src'],
           match['dl_dst'],
           match['dl_type'],
           match['dl_vlan'],
           # match['dl_vlan_pcp'],
           match['nw_proto'],
           match['nw_src'],
           match['nw_dst'],
           match['nw_tos'],
           match['tp_src'],
           match['tp_dst']
           )

    return hash(key)


def grab():
    b = server.check2()
    a = pickle.loads(b)
    return a


def flowt(table, start=0, end=float("inf")):
    a = grab()
    slice_name = raw_input("Please Enter a slice to print flows for:\t")

    with open('flowt.csv', 'w') as csvfile:
        fieldnames = ['dpid', 'hash', 'in_port', 'dl_src', 'dl_dst', 'dl_type', 'dl_vlan', 'nw_proto', 'nw_src',
                      'nw_dst', 'nw_tos', 'tp_src', 'tp_dst', 'Packet_Counter', 'Packet_In','Slice_Owner']

        writer = csv.DictWriter(csvfile, fieldnames = fieldnames)
        writer.writeheader()

        for kk, vv in a[table].iteritems():
            for l, w in vv.iteritems():
                if w['timestamps']['start'] > start and w['timestamps']['end'] < end and w['slice_Owner'] == slice_name:

                    b = w['match']
                    b['dpid'] = kk
                    b['hash'] = l
                    b['Packet_Counter'] = w['counters']['counterX']
                    b['Packet_In'] = w['counters']['PacketIn']
                    b['Slice_Owner'] = w['slice_Owner']
                    writer.writerow(b)


def active():
    print 'Printing Active Counters\n\n'
    flowt(0)


def expired():
    print 'Printing Expired Counters\n\n'
    flowt(1)


def aggregate():
    print 'Printing Aggregate Counters\n\n'
    a = grab()
    aggr = a[0]
    for dpid, rest in a[1].iteritems():
        for hashes, dicts in rest.iteritems():
            hk = construct_hashed_sflow(dicts['match'])

            print 'Hash Key: %s' % hk
            if dpid not in aggr:
                aggr[dpid] = {}
                aggr[dpid][hk] = dicts
                aggr[dpid][hk]['counters']['PacketIn'] = 1
            elif hk not in aggr[dpid]:
                aggr[dpid][hk] = dicts
                aggr[dpid][hk]['counters']['PacketIn'] = 1
            else:
                aggr[dpid][hk]['counters']['counterX'] += dicts['counters']['counterX']
                try:
                    aggr[dpid][hk]['counters']['PacketIn'] += 1
                except KeyError:
                    aggr[dpid][hk]['counters']['PacketIn'] = 1

    print '\n'

    with open('aggregates.csv', 'w') as csvfile:
        fieldnames = ['dpid', 'hash', 'in_port', 'dl_src', 'dl_dst', 'dl_type', 'dl_vlan', 'nw_proto', 'nw_src',
                      'nw_dst', 'nw_tos', 'tp_src', 'tp_dst', 'Packet_Counter', 'Packet_In','Slice_Owner']

        writer = csv.DictWriter(csvfile, fieldnames = fieldnames)
        writer.writeheader()
        slice_name = raw_input("Please Enter a slice to print flows for:\t")

        for kk, vv in aggr.iteritems():
            for l, w in vv.iteritems():
                if w['slice_Owner'] == slice_name:
                    # TODO add field rows (test it)
                    b = w['match']
                    b['dpid'] = kk
                    b['hash'] = l
                    b['Packet_Counter'] = w['counters']['counterX']
                    b['Packet_In'] = w['counters']['PacketIn']
                    b['Slice_Owner'] = w['slice_Owner']

                    writer.writerow(b)


def timewindows():
    print "Current time is: %s" % time.strftime('%d.%m.%Y %H:%M:%S', time.localtime(time.time()))

    # Enter local time
    # Look up conversion of date in time.time format
    print "Please use ONLY the following format: d.m.Y H:M:S"
    start = raw_input("Please enter from where to start:\t")
    if not start:
        start = 0
    else:
        start = int(time.mktime(time.strptime(start, "%d.%m.%Y %H:%M:%S")))

    end = raw_input("Please enter from where to end:  \t")

    if not end:
        end = float("inf")
    else:
        end = int(time.mktime(time.strptime(end, "%d.%m.%Y %H:%M:%S")))

    # Select between Active or Expired
    table = raw_input("Select:\n0: \t Active\n1: \t Expired\n\n")
    while table not in ['0', '1']:
        print "Select 0 or 1"
        table = raw_input("Select:\n0: \t Active\n1: \t Expired\n\n")

    print 'Printing Counters for timewindow %s %s \n\n' % (start, end)

    if table == 0:
        print 'Printing Active Counters\n\n'
    else:
        print 'Printing Expired Counters\n\n'

    flowt(int(table), start, end)


def check4():
    b = server.check_flowspace()
    a = pickle.loads(b)
    print a
    return a


if __name__ == '__main__':
    print 'Enter:'
    print '1:\t Active'
    print '2:\t Expired'
    print '3:\t Aggregates'
    print '4:\t Select timewindows'
    print '5:\t to exit\n\n'

    choice = raw_input("Please Enter a valid option:\t")
    print "\n\n"
    choices = ['1', '2', '3', '4', '5']
    option = {'1': active,
              '2': expired,
              '3': aggregate,
              '4': timewindows,
              '5': sys.exit}

    while True:
        while choice not in choices:
            choice = raw_input("Please Enter a valid option:\t")
            print "\n\n"
        option[choice]()
        choice = None