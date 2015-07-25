#!/usr/bin/python

import os
import sys
import pickle
import jsonrpclib

# Create a mapping between sflow agent ID and DPID
sflow_dpid = {}

# Crate a new object of class jsonrpclib.Server
server = jsonrpclib.Server('http://localhost:8080')


# https://stackoverflow.com/questions/1283061/python-capture-popen-stdout-and-display-on-console
def call_and_peek_output(cmd, shell=False):
    import pty
    import subprocess
    # Create a new pair master, slave
    master, slave = pty.openpty()
    print cmd
    p = subprocess.Popen(cmd, shell=shell, stdin=None, stdout=slave, close_fds=True)
    os.close(slave)
    line = ""
    while True:
        try:
            ch = os.read(master, 1)
        except OSError:
            # We get this exception when the spawn process closes all references to the
            # pty descriptor which we passed him to use for stdout
            # (typically when it and its childs exit)
            break
        line += ch
        if ch == '\n':
            yield line
            line = ""
    if line:
        yield line

    ret = p.wait()
    if ret:
        raise subprocess.CalledProcessError(ret, cmd)


def separate_fields(mystr):
    """
    :params: string
    separating mystr into two parts, field - value pairs.
	:returns: pair of field and its value
    """
    p = mystr.rfind(' ')
    field = mystr[:p]
    value = mystr[p+1:-2]
    if field == "TCPDstPort" or field == "UDPDstPort":
        field = "DstPort"
    elif field == "TCPSrcPort" or field == "UDPSrcPort":
        field = "SrcPort"
         
    return (field, value)


def sflowParser():
    print sflow_dpid

    # Fields we are interested in keeping from an sflow sample
    tuples = ['sourceId', 'inputPort', 'outputPort', 'srcMAC', 'dstMAC',
              'in_vlan', 'IPProtocol', 'srcIP', 'dstIP', 'IPTOS', 'headerBytes',
              'SrcPort', 'DstPort', 'ICMPType', 'ICMPCode']
    # flag to identify sample start - end
    switch = 0

    for l in call_and_peek_output(['sflowtool -p %s' % sys.argv[1]], shell=True):
        # ---- Condition to grab the 1st line where a new flowsample starts
        if 'FLOWSAMPLE' in l:
            switch = 1
            flow = {}

        # ---- Condition to identify where the flowsample ends
        if switch == 1 and "endSample" in l:
            # set flag to 0
            switch = 0

            # process samples

            # support for field, ethernet type protocol using header values
            b = flow['headerBytes'].split('-')
            ether_type = b[12] + b[13]
            flow['dl_type'] = int(ether_type, 16)

            if ether_type == '0806':
                flow['srcIP'] = str(int(b[28], 16)) + '.' + str(int(b[29], 16)) + '.' \
                                + str(int(b[30], 16)) + '.' + str(int(b[31], 16))

                flow['dstIP'] = str(int(b[38], 16)) + '.' + str(int(b[39], 16)) + '.' \
                                + str(int(b[40], 16)) + '.' + str(int(b[41], 16))

                flow['IPProtocol'] = int(b[20] + b[21], 16)

            l = ''
            m = ''

            #  construct mac address with colons
            for k in (0, 2, 4, 6, 8, 10):
                l = l + flow['srcMAC'][k:k+2] + ':'
                m = m + flow['dstMAC'][k:k+2] + ':'

            # Remove last colon
            flow['srcMAC'] = l[:17]
            flow['dstMAC'] = m[:17]

            # added dictionary mapping, or default situational mininet support
            if not sflow_dpid:
                flow['sourceId'] = flow['sourceId'][3:]
                flow['dpid'] = str(int(flow['sourceId']) + 1)
            else:
                flow['dpid'] = sflow_dpid[flow['sourceId']]

            print 'flow:'
            print flow

            b = pickle.dumps(flow)
            #if 'outputPort' in flow:
             #   server.collect_sflow(b)
            #else:
             #   print 'packet in Sampled\n'
            # The above is used not to double-count the flows, since counter is initialized in one
            # The above has to be modified since in our case we drop traffic

            try:
                server.collect_sflow(b)
            except:

                print 'Unknown Error'

        # ---- Condition to split the fields of flowsamples
        if switch == 1:
            field, value = separate_fields(l)
            if field in tuples:
                flow[field] = value

            
if __name__ == "__main__":
    a = len(sys.argv)
    if a == 2:
        sflowParser()
    elif a == 3:
        file_name = sys.argv[2]
        try:
            # construct sflow_dpid mapping based on a file
            with open(file_name) as f:
                for line in f:
                    (key, val) = line.split()
                    sflow_dpid[key] = val

            sflowParser()
        except IOError:
            print "\nNo such file: \t%s\n" % file_name
            print "Provide EXACTLY two arguments <target_port> <filename> (JSON Format)\n"
    else:
        print "Wrong Usage: Provide EXACTLY two arguments <target_port> <filename> (JSON Format)"
        exit()
