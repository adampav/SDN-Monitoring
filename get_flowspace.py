#!/usr/bin/python

import os
import sys
import ast
import jsonrpclib
import pickle

server = jsonrpclib.Server('http://10.0.0.2:8080')

a = list()

def call_and_peek_output(cmd, shell=False):
    import pty
    import subprocess
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
    p = mystr.rfind(' ')
    field = mystr[:p]
    value = mystr[p+1:-2]
    if field == "TCPDstPort" or field == "UDPDstPort":
        field = "DstPort"
    elif field == "TCPSrcPort" or field == "UDPSrcPort":
        field = "SrcPort"
         
    return (field, value)


def flowvisor_parser():
    # cycle_timout = Time-window for the detection // action = A.D. method
    # tuple=['timestamp', 'IPProtocol','srcIP', 'dstIP', 'IPTOS', 'TCPSrcPort', 'TCPDstPort']
    # ta fields pou mas endiaferei na kratisoume apo ta sflowsamples
    for l in call_and_peek_output('fvctl -n list-flowspace', shell=True):
        try:
            k = ast.literal_eval(l)
            a.append(k)
        except SyntaxError:
            print "First Line"

    print len(a)
    for k in range(0,len(a)):
        print a[k]

    fe = tuple(a)
    # print fe
    c = pickle.dumps(fe)
    server.update_flowspace(c)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        flowvisor_parser()
    else:
        print "Wrong Usage: Provide NO arguments"
        exit()