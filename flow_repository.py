#!/usr/bin/python

from jsonrpclib.SimpleJSONRPCServer import SimpleJSONRPCServer
import pickle
import hashlib
from struct import unpack
from socket import inet_aton

# Global Dictionaries

# Active Flows
active = {}

# Expired Flows
expired = {}

# Used as a MAC Table, matching OF ports to MAC addresses
mac_table = {}

# List to save flowspace
flowspace = []

# Structure to match sflow fields to OpenFlow fields
mapper = {'inputPort': 'in_port',
          'srcMAC': 'dl_src',
          'dstMAC': 'dl_dst',
          'IPTOS': 'nw_tos',
          'IPProtocol': 'nw_proto',
          'srcIP': 'nw_src',
          'dstIP': 'nw_dst'}

def check_flowspace():
    """
	:params None

	:rtype : Serialized version of flowspace
    """
    # print flowspace
    a = pickle.dumps(flowspace)
    return a


def check2():
    """
	:params None
	:rtype : Serialized tuple containing active and expired dictionaries
    """
    args = (active,expired)
    b = pickle.dumps(args)
    return b


def update_flowspace(serial):
    """
	:params serialized version of flowspace
    """
    # TODO delete previous flowspace (or keep a diff)
    # Update Flowspace
    print 'Updated'
    space = pickle.loads(serial)
    for l in range(0, len(space)):
        flowspace.append(space[l])


def assign_flowspace(hash_val, dpid):
    """
	:params hashed value of our flow rule and dpid
	:rtype
    """

    flow_fields = ['in_port', 'dl_src', 'dl_dst', 'dl_type', 'dl_vlan',
	               'nw_proto', 'nw_src', 'nw_dst', 'nw_tos', 'tp_src', 'tp_dst']

    # List throught all flowspace rules
    for a in range(0, len(flowspace)):
        # if we examine a flowspace rule that refers to another dpid, continue
        if flowspace[a]['dpid'][-1] != dpid:
            continue
        # for every match field
        for k in flow_fields:
            if k not in flowspace[a]['match']:
                # wildcard in flow space so we dont care
                # print '1'
                continue
            elif active[dpid][hash_val]['match'][k] is None:
                # flowspace field is not a wildcard
                # if flow space does not  have the same value, break
                # print '2'
                break
            elif flowspace[a]['match'][k] == active[dpid][hash_val]['match'][k]:
                # if both above conditions are not met, check if their values are identical
				#print '3'
                continue
            else:
                # special treatment for ip subnets
                if (k == 'nw_src') or (k == 'nw_dst'):
                    # split flowspace and openflow rules to A.B.C.D/M format
                    fsp = flowspace[a]['match'][k].split('/')
                    frl = active[dpid][hash_val]['match'][k].split('/')

                    if len(fsp) == 1:
                        # if length is equal to 1 its just an IP ( A.B.C.D ) not a subnet
                        break
                    else:
                        # A.B.C.D/M
                        tmp = int (fsp[1])
                        # convert equivalent subnet mask (M)
                        fsp_mask = int ((tmp* '1' + (32 - tmp) * '0'), 2)

                        if len(frl) == 1:
                            # check if flow rule is a a.b.c.d
							# Then Check if (A.B.C.D && M == a.b.c.d)
                            if (unpack("!L", inet_aton(frl[0]))[0] & fsp_mask) == unpack("!L", inet_aton(fsp[0]))[0]:
                                continue
                            else:
                                break
                        else:
                            # flow rule is a.b.c.d/m
							# do the same but this time check if flow rule refers to a subset of flowspace
                            tmp = int (frl[1])
                            frl_mask = int ((tmp * '1' + (32 - tmp) * '0'), 2)

                            if frl_mask > fsp_mask:
                                break
                            elif (unpack("!L", inet_aton(frl[0]))[0] & fsp_mask) == unpack("!L", inet_aton(fsp[0]))[0]:
                                continue
                            else:
                                break

                else:
                    # not same value, (or something else)
                    # print '4'
                    break

        else:
            # exhausted flow rule, so flowspace is found
            active[dpid][hash_val]['slice_Owner'] = flowspace[a]['slice-action'][0]['slice-name']
            break
    else:
        # not part of any flowspace
        print 'Not part of any flowspace'
        active[dpid][hash_val]['slice_Owner'] = None


def return_active():
    pass


def return_expired():
    pass


def construct_hashed_key(match, time_s=None, hash_f=1):
    """
	:params (OpenFlow match, timestamp, flag)
	Depending on the value of hash_f returns different
    hashed objects
    :rtype : hashed value
    """
    key = (match.in_port,
           match.dl_src.toStr(),
           match.dl_dst.toStr(),
           match.dl_type,
           match.dl_vlan,
           # match.dl_vlan_pcp,
           match.nw_proto,
           match.nw_src.toStr(),
           match.nw_dst.toStr(),
           match.nw_tos,
           match.tp_src,
           match.tp_dst,
           time_s)
    # print 'printing the values of our soon to be hashed key'
    # print key

    if hash_f == 1:
        #if hash_f == 1, don't include the timestamp parameter
        print hash(key[:len(key) -1])
        return hash(key[:len(key)-1])
    else:
        # else include it
        print hash(key[:len(key) -1])
        return hash(key)


def construct_hashed_sflow(match):
    """
    :param match: OpenFlow match object
    :return: hashed value
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

    # print key
    print hash(key)
    return hash(key)

def construct_dict(match, dpid):
    """
    :param match: OpenFlow match object, dpid
    :return: dictionary with those values
    """
    di = {}
    di['in_port'] = match.in_port
    di['dl_src'] = match.dl_src.toStr()
    di['dl_dst'] = match.dl_dst.toStr()
    di['dl_type'] = match.dl_type
    di['dl_vlan'] = match.dl_vlan
    # di['dl_vlan_pcp'] = match.dl_vlan_pcp
    di['nw_proto'] = match.nw_proto
    di['nw_src'] = match.nw_src.toStr()
    di['nw_dst'] = match.nw_dst.toStr()
    di['nw_tos'] = match.nw_tos
    di['tp_src'] = match.tp_src
    di['tp_dst'] = match.tp_dst
    di['dpid'] = dpid
    return di


def construct_new_entry(serialized_match):
    """
    :param match: serialized OpenFlow match
    """
    args = pickle.loads(serialized_match)
    match = args[0]
    dpid = args[1]
    time = float(args[2])
    # print '\n\n___Installing New Entry___'

	# Construct hashed value based on match
    d = construct_hashed_key(match)

    # print ("Switch: %s,\t Flow(Hash): %s" % (dpid, d))

    # Check if the dpid entry has been initialized
    if dpid not in active:
        active[dpid] = {}

    # Creating the Flow Entry
	# if the flow rule is not already in the Active structure
    if d not in active[dpid]:
        active[dpid][d] = {'counters': {'counterX': 1, 'Packet_In': 1, 'mult_Packet_in': 1},
                           'match': construct_dict(match, dpid),
                           'timestamps': {'start': time, 'end': None},
                           'headers': {},
                           'slice_Owner': None
                           }
        hlp = active[dpid][d]['match']

        if dpid not in mac_table:
            mac_table[dpid] = {}
            mac_table[dpid][hlp['dl_src']] = hlp['in_port']
        else:
            mac_table[dpid][hlp['dl_src']] = hlp['in_port']

        # assign the flow entry to a flowspace
        # assign_flowspace(d, dpid)
	# else increment a counter measuring multiple packetIns
    else:
        active[dpid][d]['counters']['mult_Packet_in'] += 1


    # MAC Table
    if dpid not in mac_table:
        mac_table[dpid] = {}
        mac_table[dpid][hlp['dl_src']] = hlp['in_port']
    else:
        mac_table[dpid][hlp['dl_src']] = hlp['in_port']

    # assign_flowspace(d, dpid)


def move_to_expired(serialized_match):
    """
    :param match: serialized OpenFlow match
    :return:
    """
    args = pickle.loads(serialized_match)
    match = args[0]
    dpid = args[1]
    time = float(args[2])
    # print "\n\n___Moving Expired Entry___"

	# create a hash value for the expired flow (not including timestamp)
    e = construct_hashed_key(match)

    # if there is such a flow
    if e in active[dpid]:
        # remove the flow
        found = active[dpid].pop(e)
        found['timestamps']['end'] = time

        # now create another hashed value, including timestamp
        d = construct_hashed_key(match, found['timestamps']['start'], 0)

        if dpid not in expired:
            expired[dpid] = {}

        expired[dpid][d] = found
        if active[dpid] == {}:
            del active[dpid]


def collect_sflow(flow):
    """
    :param match: serialized sflow sample
    :return:
    """

    # print '\n\n___Incrementing Counter Entry___'
    sflow = {}

    b = pickle.loads(flow)

    # TODO will try with sflow = b
    for kk, vv in b.iteritems():
        sflow[kk] = vv

    # transition from sflow fields {} to, openflow match {}
    match = {}

    # convert dl_type
    dpid = sflow.pop('dpid')
    match['dl_type'] = sflow.pop('dl_type')

    # manipulate VLAN tag
    if sflow['in_vlan'] == '0':
        match['dl_vlan'] = 65535
        del sflow['in_vlan']
    elif sflow['in_vlan'] is not None:
        match['dl_vlan'] = int(sflow.pop('in_vlan'))
    else:
        match['dl_vlan'] = None

    # unifying UDP/TCP/ICMP or wildcarding
    if 'SrcPort' in sflow:
        # no need to check for Dst Port, since this is a sample and bound to have DST aswell
        match['tp_src'] = int(sflow['SrcPort'])
        match['tp_dst'] = int(sflow['DstPort'])
    elif 'ICMPType' in sflow:
        match['tp_src'] = int(sflow['ICMPType'])
        match['tp_dst'] = int(sflow['ICMPCode'])
    else:
        match['tp_src'] = None
        match['tp_dst'] = None

    fields = ['inputPort', 'srcMAC', 'dstMAC',
              'IPProtocol', 'srcIP', 'dstIP', 'IPTOS']

    intfields = ['inputPort', 'IPProtocol', 'IPTOS']

    # translate rest of the fields using the structure mapper{}
    for a in fields:
        if a not in sflow:
            match[mapper[a]] = None
        elif a in intfields:
            match[mapper[a]] = int(sflow.pop(a))
        else:
            match[mapper[a]] = sflow.pop(a)

    # modify ingress port using mac_table
    match['in_port'] = mac_table[dpid][match['dl_src']]

    # print 'OpenFlow Match:'
    # print match

    try:
        d = construct_hashed_sflow(match)

        print 'Printing Hash: %d\n\n' % d
        # print 'Printing of all flows of the DPID: %s' % dpid
        # print active[dpid]

        if d in active[dpid]:
            print 'Hash Found'
            active[dpid][d]['counters']['counterX'] += 1
            # adding headers of packet

            # f = match['headerBytes']
            # e = hash(f)
            # if e not in active[dpid][d]['headers']:
            #    active[dpid][d]['headers'][e] = f

            # print active
        else:
            print 'Hash not found'
            # same functionality as in assign_flowspace()
            for kk, vv in active[dpid].iteritems():
                for ll, ww in vv['match'].iteritems():
                    if ww is None:
                        # can continue with next iteration
                        continue
                    elif (ll not in match) or (match[ll] is None):
                        # key error will not be raised, because if key not present second 'or' will not be evaluated
                        break
                    elif match[ll] == ww:
                        # if sample attribute is equal with the match then we have no difference
                        continue
                    else:
                        if (ll == 'nw_src') or (ll == 'nw_dst'):
                            # special support for ip
                            frl = ww.split('/')
                            if len(frl) == 1:
                                # A.B.C.D
                                # should have been caught by outer elif
                                break

                            # A.B.C.D/M
                            tmp = int(frl[1])
                            frl_mask = int((tmp * '1' + (32 - tmp) * '0'), 2)
                            # sflow: a.b.c.d
                            if (unpack("!L", inet_aton(match[ll]))[0] & frl_mask) == unpack("!L", inet_aton(frl[0]))[0]:
                                continue
                            else:
                                break
                        else:
                            # not same value, (or something else)
                            # print '4'
                            break
                else:
                    # if loop is completed with no breaks this value under investigation should be incremented
                    active[dpid][kk]['counters']['counterX'] += 1
                    print 'Flow Reconstructed'
                    break
            else:
                print 'Hash Reconstrution failed.\n'
    except:
        print 'Error caught.\nPrinting match field'
        print sflow
        print match
        print 'This should not have happened'
    # print ("Switch: %s,\t sFlow(Hash): %s" % (dpid, d))


if __name__ == "__main__":
    # binding server to port
    server = SimpleJSONRPCServer(('localhost', 8080))

    # register functions for usage
    server.register_function(construct_new_entry)
    server.register_function(move_to_expired)
    server.register_function(collect_sflow)
    server.register_function(check_flowspace)
    server.register_function(check2)
    server.register_function(update_flowspace)

    # start server
    server.serve_forever()