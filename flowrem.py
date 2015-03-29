from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
from pox.openflow import *
from pox.forwarding import l2_learning
import os
import pickle
import jsonrpclib
import time

log = core.getLogger()
log1 = core.getLogger("Flow Installed")
log2 = core.getLogger("Flow Removed")
server = jsonrpclib.Server('http://83.212.121.12:8080')

class CustomEvent(Event):
  """
  Our own custom event
  """
  def __init__(self, connection, ofp):
    Event.__init__(self)
    self.connection = connection
    self.ofp = ofp
    self.dpid = connection.dpid

class EventSourcer (EventMixin):
  """
  Our event raise class. Can only raise CustomEvent
  """
  _eventMixin_events = set([
    CustomEvent,
  ])

handler = EventSourcer()

class FlowRemovalHandler (EventMixin):


    def __init__ (self):
        self.listenTo(core.openflow)
        self.listenTo(handler)
        log.debug("...Enabling Flow Removal Module...")

    def _handle_CustomEvent (self, event):
#        log1.debug('Flow Installed on switch: %s', event.connection)
#        log1.debug(event.ofp.match)

        args = ()
        connction = event.connection
        args = (event.ofp.match, str(connction),str(time.time()))
        b = pickle.dumps(args)

        a = server.construct_new_entry(b)
        c = pickle.loads(a)


    def _handle_FlowRemoved (self, event):

        args = ()
        connection = event.connection
        args = (event.ofp.match, str(connection), str(time.time()))
        b = pickle.dumps(args)
        a = server.move_to_expired(b)
        c = pickle.loads(a)
        log2.debug('Flow Removed from switch: %s', event.connection)
  #      log2.debug(c)



def launch ():
    '''
    Starting the module
    '''
    core.registerNew(FlowRemovalHandler)

def invoker (con, msg):
    '''
    When called raises CustomEvent
    '''
    handler.raiseEvent(CustomEvent(con,msg))
