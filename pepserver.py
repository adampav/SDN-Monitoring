from jsonrpclib.SimpleJSONRPCServer import SimpleJSONRPCServer
import pickle
import os
import hashlib
m = hashlib.md5()

active={}
expired={}


def check():
    print active
    print expired

def return_active():
    pass

def return_expired():
    pass

def construct_hashed_key(match, time_s=None, hash_f=1):
    key = (match.in_port,
           match.dl_src,
           match.dl_dst,
           match.dl_type,
           match.dl_vlan,
           #match.dl_vlan_pcp,
           match.nw_proto,
           match.nw_src,
           match.nw_dst,
           match.nw_tos,
           match.tp_src,
           match.tp_dst,
           time_s)
    if hash_f ==1:
        return hash(key[:len(key)-1])
    else:
        return hash(key)

def construct_dict(match, dpid):
    di = {}
    di['in_port'] = match.in_port
    di['dl_src']  = match.dl_src
    di['dl_dst']  = match.dl_dst
    di['dl_type'] = match.dl_type
    di['dl_vlan'] = match.dl_vlan
#    di['dl_vlan_pcp'] = match.dl_vlan_pcp
    di['nw_proto'] = match.nw_proto
    di['nw_src'] = match.nw_src
    di['nw_dst'] = match.nw_dst
    di['nw_tos'] = match.nw_tos
    di['tp_src'] = match.tp_src
    di['tp_dst'] = match.tp_dst
    di['dpid'] = dpid
    return di

def construct_new_entry(serialized_match):
    args = pickle.loads(serialized_match)
    match = args[0]
    dpid = args[1]
    time = float(args[2])
    d = construct_hashed_key(match)

    if not active.has_key(dpid):
        active[dpid] = {}

    #Creating the Flow Entry
    active[dpid][d] = {'counters': {'counterX': 1}, 
                       'match' : construct_dict(match, dpid),
                       'timestamps' : {'start':time, 'end':None}
                      }

    print '\n___Installing New Entry___'
    print ("Switch: %s,\t Flow(Hash): %s" % (dpid, d))
    print ('\nActive Bucket\n')
    print active
    print ('\nExpired Bucket\n')
    print expired

    return pickle.dumps(match)

def move_to_expired(serialized_match):
    args = pickle.loads(serialized_match)
    match = args[0]
    dpid = args[1]
    time = float(args[2])
    e = construct_dict(match,dpid)

    for kk,vv in active[dpid].iteritems():
        if cmp(vv['match'],e) == 0:
            #both work 
            #pop() captures and deletes
            #del active[dpid][d]
            found = active[dpid].pop(kk)
            break

    found['timestamps']['end']=time

    
    d = construct_hashed_key(match,found['timestamps']['start'],0)

    if not expired.has_key(dpid):
        expired[dpid] = {}

    expired[dpid][d] = found
    
    #'if active[dpid]:' does not work
    if active[dpid] == {}:            
      del active[dpid]

    print '\n___Moving Expired Entry___'
    print ("Switch: %s,\t Flow(Hash): %s" % (dpid, d))
    print ('\nActive Bucket\n')
    print active
    print ('\nExpired Bucket\n')
    print expired

    return pickle.dumps(match)

server = SimpleJSONRPCServer(('83.212.121.12', 8080))
server.register_function(construct_new_entry)
server.register_function(move_to_expired)
server.register_function(check)
server.serve_forever()
