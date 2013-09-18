#!/usr/bin/python
#
# nids-mixer.py
#
# A NS3 based TCP layer data to simulated network projector/mixer.
# This software will use a set of .pcap traces and annotation files
# to map TCP streams from the .pcap files onto a NS3 network that
# simulates the internet, a LAN, and a router between them.  The
# router will capture all traffic, and produce a .pcap file which
# contains the replayed TCP streams in this particular simulated
# network.
#
# The internet has been modeled as a collection of nodes, all of
# which have a point-to-point link to the router.  All point-to-point
# links have arbitrary delay, throughput and loss settings that are
# randonly chosen.
#
# Bugs
# ----
# NS-3 has bugs, and not only in unidirectional closure of TCP streams, but
# also more significant ones in the Python bindings.  I expect that eventually
# they can be tracked down and fixed, but for I lack the time to debug them
# properly, and this program does not always end up running correctly.
#
# Another issue is the possible omission of a ADU_stream when the peer disappears
# and the current side gets stuck in a receive.  However, this seems easier to
# sort out when unidirectional closure has been fixed.
#
# Design issues
# -------------
# 1/ The handling of inter-packet delays are not done properly done. Currently
# we adhere to the causal ordering of packets when sending and receiving, but
# the inter-packet delays are lost when transmitting data on a slower link.
# For this to work better, we would need to keep an eye on the TX queue and
# figure out whether it is empty.  Doing so however would be unnatural, as it
# would not allow the TX buffer to hold more than one packet.  However, we do
# not yet analyze concurrency in packets.  There also does not seem to be a
# way to be notified the TX buffer has emptied in NS-3 as of yet, although
# this could be added.
#
# Fixing this is not a trivial issue, as it depends in part on the ADU
# analysis which needs to be changed.  When creating the ADUs, we need to not
# simply measure the delays between sends, but rather what sends can be
# outstanding at the same time, while not necessarily being acknowledged.  We
# can be sure the application is transmitting that data concurrently.
#
# 2/ There is currently no synchronization between ADUs in different streams.
# This is a large problem for some type of streams, such as proxy connections.
# As a proxy connection consists of two streams, which have a causal ordering
# against each other, we would now lose this ordering.  This allows one proxy
# stream to jump ahead of the other.
#
#  -- Ronald Huizer / r.huizer@xs4all.nl (c) 2013
#
import re
import sys
import random
import inspect
import ConfigParser
from scapy.all import *
from itertools import ifilter
from ns.applications import *
from ns.core import *
from ns.csma import *
from ns.internet import *
from ns.network import *
from ns.point_to_point import *

# ADUs model application layer sequencing over TCP packets, such that they can
# be derived from .pcap files to extract a causal protocol relationship.
#
# ADUs model the delay between sends on both sides, to capture application
# defined delays.  This is cleanest when using a .pcap that has been created
# on a low-latency link, as we do not have to compensate for the RTT.
class ADU:
    def __init__(self, delay=0):
        self.delay = MicroSeconds(int(delay * 1000 * 1000))

# Helper ADU for creating a new in-sequence stream.
class ADU_stream(ADU):
    def __init__(self, stream, delay=0):
        ADU.__init__(self)
        self.stream = stream

    def __repr__(self):
        return "ADU_stream"

class ADU_connect(ADU):
    def __init__(self, addr, port):
        ADU.__init__(self)
        self.addr = addr
        self.port = port

    def __repr__(self):
        return "ADU_connect"

class ADU_send(ADU):
    def __init__(self, data, delay=0):
        ADU.__init__(self, delay)
        self.data = data

    def __repr__(self):
        return "ADU_send(%d)" % len(self.data)

class ADU_recv(ADU):
    def __init__(self, size):
        ADU.__init__(self)
        self.size = size

    def __repr__(self):
        return "ADU_recv(%d)" % self.size

class ADU_shutdown(ADU):
    def __init__(self, delay=0):
        ADU.__init__(self, delay)

    def __repr__(self):
        return "ADU_shutdown"

class mixer_rx_state:
    def __init__(self):
        self.rx_len = 0
        self.rx_pending = False     # Level triggered rx signal.
        self.rx_fin = False         # We received a FIN.

# Shared routines between the mixer client and server which function as the
# event pump for both. Note that this pump only deals with one socket descriptor
# which is a limit to our model that can be addressed at a later time.
#
# Currently this disallows us from generating concurrent traces to the same
# port.
class mixer_pump(Application):
    def __init__(self, mixer):
        Application.__init__(self)
        self.mixer = mixer
        self.tag = ""

        # Per connection state.
        self.state = {}

    def log(self, msg):
        if self.tag == "":
            print "%s) %s" % (Simulator.Now(), msg)
        else:
            print "%s) %s %s" % (Simulator.Now(), self.tag, msg)

    def getsockaddr(self, sd):
        addr = Address()
        sd.GetSockName(addr)
        return InetSocketAddress.ConvertFrom(addr)

    def getpeername(self, sd):
        addr = Address()
        sd.GetPeerName(addr)
        return InetSocketAddress.ConvertFrom(addr)

    def getsockaddrstr(self, sd):
        addr = self.getsockaddr(sd)
        return "%s:%d" % (addr.GetIpv4(), addr.GetPort())

    def getpeernamestr(self, sd):
        addr = self.getpeername(sd)
        return "%s:%d" % (addr.GetIpv4(), addr.GetPort())

    def getsocketstr(self, sd):
        sockaddr = self.getsockaddrstr(sd)
        peername = self.getpeernamestr(sd)
        return "%s <-> %s" % (sockaddr, peername)

    def process_adu(self, sd, adus):
        self.log("process_adu for %s" % self.getsocketstr(sd))

        if not adus:
            self.log("No more ADUs")
            return

        adu = adus.pop(0)
        tdelta = adu.delay - (Simulator.Now() - self.last_send_time)
        self.log("ADU time delta: %s" % tdelta)

        if isinstance(adu, ADU_send):
            if tdelta <= MicroSeconds(0):
                self.log("ADU_send now")
                Simulator.ScheduleNow(self.send_adu, sd, adu, adus)
            else:
                self.log("ADU_send at %s" % tdelta)
                Simulator.Schedule(tdelta, self.send_adu, sd, adu, adus)

        elif isinstance(adu, ADU_recv):
            self.log("ADU_recv %d bytes." % adu.size)
            rx_state = self.state[self.getsocketstr(sd)]
            rx_state.rx_len = adu.size

            # This shouldn't happen, but wreaks havoc, so check it.
            if adu.size == 0:
                self.log("ADU_recv of size 0; aborting.")
                sys.exit(1)

            # If we have a pending rx notification, handle it.  Otherwise
            # we rely on the callback function to pick this up.
            #
            # XXX: can recurse for ADU_recvs in a row which are received
            # at once, which can lead to trouble...
            if rx_state.rx_pending:
                self.receive(sd, adus)

        # Ideally we would like to perform an unidirectional close here, but
        # NS-3.17 is broken with regard to shutdown handling.  When calling
        # TcpSocketBase::ShutdownSend() with Packets pending in the tx_buffer
        # sending a FIN is deferred until it empties up.
        # However, on receiving an ACK for data in the tx_buffer through
        # NewAck, it is possible for tx_buffer to empty prior to a call to
        # SendPendingData().  Normally SendPendingData() will send the FIN
        # by calling SendDataPacket(), but it shorts circuit in case of an
        # empty tx_buffer.
        # This needs to be fixed in NS-3.17 before we can properly perform
        # an unidirectional close.
        #
        #  -- R. Huizer
        #
        elif isinstance(adu, ADU_shutdown):
            self.log("ADU_shutdown")

            if tdelta <= MicroSeconds(0):
                self.log("ADU_shutdown now")
                Simulator.ScheduleNow(self.shutdown_adu, sd, adus)
            else:
                self.log("ADU_shutdown at %s" % tdelta)
                Simulator.Schedule(tdelta, self.shutdown_adu, sd, adus)

        # We have another connect.  This happens when one .pcap file contains
        # multiple streams, which we assume to be sequential in creation.  We
        # however do not synchronize the ADUs between streams once they have
        # been created.  Future work would improve on this behaviour.
        elif isinstance(adu, ADU_stream):
            self.log("ADU_stream")

            if tdelta <= MicroSeconds(0):
                self.log("ADU_stream now")
                Simulator.ScheduleNow(self.start_stream, sd, adu.stream, adus)
            else:
                self.log("ADU_stream at %s" % tdelta)
                Simulator.Schedule(tdelta, self.start_stream, sd, adu.stream, adus)

        elif isinstance(adu, ADU_connect):
            self.log("ADU_connect.  Should not happen.")
            sys.exit(1)

    def start_stream(self, sd, stream, adus):
        # Initialize a new application to handle this stream.
        self.log("start_stream")

        self.mixer.count += 1

        # See if we have a server running at the endpoint, if so queue
        # the stream there, otherwise start a new server.
        server_address = stream.get_nat_dst_addr_port()
        if server_address not in self.mixer.servers:
            self.log("starting new server")
            mix_srv = mixer_server(self.mixer, stream)
            mix_srv.node.AddApplication(mix_srv)
            self.mixer.servers[server_address] = mix_srv
        else:
            self.log("existing server found: %s:%d" % server_address)
            self.mixer.servers[server_address].add_stream(stream)

        mix_client = mixer_client(self.mixer, stream)
        mix_client.SetStartTime(NanoSeconds(1))
        mix_client.node.AddApplication(mix_client)

        self.last_send_time = Simulator.Now()
        self.process_adu(sd, adus)

    def shutdown_adu(self, sd, adus):
        self.log("shutdown_adu")
        sd.Close()
        self.last_send_time = Simulator.Now()
        self.process_adu(sd, adus)

    def send_adu(self, sd, adu, adus):
        ret = sd.Send(Packet(adu.data), 0)
        if ret == -1:
            self.log("send_adu: Send failed: %d" % sd.GetErrno())
        else:
            self.log("send_adu: %d bytes of data." % ret)

        self.last_send_time = Simulator.Now()
        self.process_adu(sd, adus)

    def receive(self, sd, adus):
        self.log("receive for %s" % self.getsocketstr(sd))
        rx_state = self.state[self.getsocketstr(sd)]

        # Received an early ADU.  Level trigger it, and back off.
        if rx_state.rx_len == 0:
            rx_state.rx_pending = True
            return

        # As long as we're supposed to rx data, we will block doing so.
        while rx_state.rx_len != 0:
            packet = sd.Recv(rx_state.rx_len, 0)
            # We have not received all data, so we return until we get a
            # notification for the next packet.
            if packet is None:
                self.log("Incomplete ADU; expecting %d more bytes" % rx_state.rx_len)
                rx_state.rx_pending = False
                return

            self.log("received %d bytes." % packet.GetSize())
            rx_state.rx_len -= packet.GetSize()

        # We have processed the entire ADU rx_len, so carry on.  We set
        # rx_pending, as the NS3 API could be edge triggered (need to verify
        # this), so in case Recv() has not consumed all data left, we do not
        # want to block.  Doing this once can result in an unnecessary call to
        # receive(), but a None packet should then clear this flag until the
        # next edge.
        rx_state.rx_pending = True
        self.process_adu(sd, adus)

    # The normal close handler triggers on a FIN from the connection peer.
    # We close the recv half of our socket, and only fully clean it up when
    # we signal a FIN ourselves.
    #
    # XXX: See explanation before on why we do not shutdown.
    def normal_close(self, sd):
        self.log("Received FIN for %s" % self.getsockaddrstr(sd))

        # XXX: kludge; this works around a NS3 bug where error close is called
        # the endpoint is torn down, and then close is called.  This fails as
        # the endpoint is gone, calling error close...  The endpoint gone
        # results in address/port 0.0.0.0:0 though, so we can test this.
        if self.getsockaddr(sd).GetPort() != 0:
            sd.Close()

    def error_close(self, sd):
        self.log("Error close")

# The NS3 application that will perform mixing of the TCP streams represented
# by ADUs.
class mixer_server(mixer_pump):
    def __init__(self, mixer, stream):
        mixer_pump.__init__(self, mixer)
        self.mixer = mixer
        self.streams = {}
        self.add_stream(stream)

        # Set the destination address and our node.
        self.daddr = stream.get_nat_dst_addr()
        self.dport = stream.dport
        self.node = self.mixer.t.get_node_by_addr(self.daddr)

        self.tag = "[Server]"

    # Add a stream to handle on this server.
    def add_stream(self, stream):
        saddr = stream.get_nat_src_addr()
        self.log("adding stream %s:%d" % (saddr, stream.sport))
        self.streams[(saddr, stream.sport)] = stream

    def get_stream(self, sd):
        peername = self.getpeername(sd)
        addr = (str(peername.GetIpv4()), peername.GetPort())

        if addr not in self.streams:
            self.log("get_stream: socket we do not serve...")
            return None

        return self.streams[addr]

    def StartApplication(self):
        self.accept_sd = Socket.CreateSocket(self.node, TcpSocketFactory.GetTypeId())
        self.accept_sd.SetAcceptCallback(self.connection_request, self.connection_created)
        sin = InetSocketAddress(Ipv4Address(self.daddr), self.dport)

        # Attempt to bind, if this fails, there is a port collision between
        # streams, and we will allow the server to reallocate a port.
        if self.accept_sd.Bind(sin) == -1:
            self.log("Port collision, drats...")

        self.accept_sd.Listen()
        self.log("Started serving on %s:%d" % (self.daddr, self.dport))

    def StopApplication(self):
        self.log("StopApplication")

    # Always accept the connection.
    def connection_request(self, sd, address):
        return True

    # XXX: kludge, NS-3 python bindings do not allow passing multiple
    # arguments to the SetRecvCallback handler.  We solve it like this.
    def receive_hack(self, sd):
        stream = self.get_stream(sd)
        self.receive(sd, stream.server_adus)

    def connection_created(self, sd, address):
        self.log("Connection accepted from %s" % self.getpeernamestr(sd))
        stream = self.get_stream(sd)

        # XXX: kludge because we do not do TX flow control.
        sd.SetAttribute("SndBufSize", UintegerValue(2000000000));
        sd.SetAttribute("RcvBufSize", UintegerValue(2000000000));
        sd.SetRecvCallback(self.receive_hack)
        sd.SetCloseCallbacks(self.normal_close, self.error_close)

        # XXX: another kludge, track state in a nicer way.  Per stream
        # state tracking is a bit all over the place like this.
        self.state[self.getsocketstr(sd)] = mixer_rx_state()

        self.last_send_time = Simulator.Now()
        self.process_adu(sd, stream.server_adus)

class mixer_client(mixer_pump):
    def __init__(self, mixer, stream):
        mixer_pump.__init__(self, mixer)
        self.mixer = mixer
        self.stream = stream

        # Set the destination address and our node.
        self.saddr = stream.get_nat_src_addr()
        self.daddr = stream.get_nat_dst_addr()
        self.node = self.mixer.t.get_node_by_addr(self.saddr)

        self.tag = "[Client %s|%d]" % (stream.container_name, mixer.count)

    # XXX: kludge, NS-3 python bindings do not allow passing multiple
    # arguments to the SetRecvCallback handler.  We solve it like this.
    def receive_hack(self, sd):
        self.receive(sd, self.stream.client_adus)
      
    def connection_complete(self, sd):
        self.log("Connected: %s" % self.getpeernamestr(sd))
        self.state[self.getsocketstr(sd)] = mixer_rx_state()
        self.sd.SetCloseCallbacks(self.normal_close, self.error_close)
        self.sd.SetRecvCallback(self.receive_hack)
        self.last_send_time = Simulator.Now()
        self.process_adu(self.sd, self.stream.client_adus)

    def connection_failed(self, sd):
        self.log("Failed to open connection.  Closing socket.")
        sd.Close()

    def StartApplication(self):
        self.log("StartApplication")
        adu = self.stream.client_adus.pop(0)

        if not isinstance(adu, ADU_connect):
            self.log("Warning: no CONNECT ADU.")
            return

        # Create the connection.  The first ADU should specify this.
        self.sd = Socket.CreateSocket(self.node, TcpSocketFactory.GetTypeId())
        self.sd.SetConnectCallback(self.connection_complete, self.connection_failed)

        # Bind the client half to the same port.
        sin = InetSocketAddress(Ipv4Address(self.saddr), self.stream.sport)
        if self.sd.Bind(sin) == -1:
            self.log("Bind() failed: %d" % self.sd.GetErrno())
            return

        self.log("Bound to %s:%d" % (self.saddr, self.stream.sport))

        # XXX: kludge because we do not do TX flow control.
        self.sd.SetAttribute("SndBufSize", UintegerValue(2000000000));
        self.sd.SetAttribute("RcvBufSize", UintegerValue(2000000000));

        # Translate address for connection.
        sin = InetSocketAddress(Ipv4Address(self.daddr), self.stream.dport)
        if self.sd.Connect(sin) == -1:
            self.log("Connect failed: %d" % self.sd.GetErrno())
            sys.exit(1)

        self.log("Connecting to %s:%d" % (self.daddr, self.stream.dport))

# We model an internet node as a P2P link with random delays and data rates.
# The router will be at p2p_nodes[0], and the internet node at p2p_nodes[1]
class internet_node:
    def __init__(self, router, ip):
        p2p_help = PointToPointHelper()
        p2p_help.SetChannelAttribute("Delay", self.random_delay())
        p2p_help.SetDeviceAttribute("DataRate", self.random_data_rate())

        self.p2p_nodes = NodeContainer()
        self.p2p_nodes.Add(router)
        self.p2p_nodes.Create(1)
        self.p2p_devices = p2p_help.Install(self.p2p_nodes)

        # Set the error model.
        em = RateErrorModel()
        em.SetAttribute("ErrorRate", DoubleValue(0.00001))
        self.p2p_devices.Get(0).SetAttribute("ReceiveErrorModel", PointerValue(em))
        self.p2p_devices.Get(1).SetAttribute("ReceiveErrorModel", PointerValue(em))

        # Add this node to the internet stack.
        inet_stack = InternetStackHelper()
        inet_stack.Install(self.node())

        # Assign it an IP address.
        self.ip_help = Ipv4AddressHelper()
        self.ip_help.SetBase(Ipv4Address(ip), Ipv4Mask("255.255.255.252"))
        self.p2p_interfaces = self.ip_help.Assign(self.p2p_devices)

        for i in xrange(0, self.p2p_interfaces.GetN()):
            print i, self.p2p_interfaces.GetAddress(i)

    # Between 3 and 100ms -- See "On the Internet Delay Space Dimensionality"
    @staticmethod
    def random_delay():
        return TimeValue(MilliSeconds(random.randint(3, 100)))

    # Random data rate.  Pick something between 256Kbps and 400Mpbs
    @staticmethod
    def random_data_rate():
        rates = [ "256Kbps", "512Kbps", "1Mbps",
                  "10Mbps", "100Mbps", "400Mbps" ]
        return StringValue(rates[random.randint(0, len(rates) - 1)])

    def node(self):
        return self.p2p_nodes.Get(1)

    def address(self):
        return self.p2p_interfaces.GetAddress(1)

class internet_model:
    def __init__(self, router):
        self.nodes = []
        self.router = router

        # Add the router to the internet stack.
        inet_stack = InternetStackHelper()
        inet_stack.Install(self.router)

        # Create the address/device map for the internet.
        m = {}
        for node in self.nodes:
            assert node.p2p_interfaces.GetN() == 2
            assert node.p2p_devices.GetN() == 2

            for i in range(0, 2):
                address = node.p2p_interfaces.GetAddress(i)
                m[address.Get()] = node.p2p_devices.Get(i)

        self._address_map = m

    def add_node(self, node):
        assert node.p2p_interfaces.GetN() == 2
        assert node.p2p_devices.GetN() == 2

        for i in range(0, 2):
            address = node.p2p_interfaces.GetAddress(i)
            self._address_map[address.Get()] = node.p2p_devices.Get(i)

        self.nodes.append(node)

    def addresses(self):
            return [n.address() for n in self.nodes]

    def random_address(self):
        addrs = self.addresses()
        return addrs[random.randint(0, len(addrs) - 1)]

class lan_model:
    def __init__(self, router, nodes=10):
        # Create the LAN environment.
        self.nodes = NodeContainer()
        self.router = router
        self.nodes.Create(nodes)

        # Create the CSMA devices for the nodes.
        csma = CsmaHelper()
        csma.SetChannelAttribute("DataRate", StringValue("1000Mbps"))
        csma.SetChannelAttribute("Delay", StringValue("6560ns"))

        c = NodeContainer()
        c.Add(self.router)
        c.Add(self.nodes)
        self.devices = csma.Install(c)

        # Add the CSMA nodes to the internet stack.
        inet_stack = InternetStackHelper()
        inet_stack.Install(self.nodes)

        # Assign it an IP address.
        ip_help = Ipv4AddressHelper()
        ip_help.SetBase(Ipv4Address("192.168.0.0"), Ipv4Mask("255.255.255.0"))
        self.interfaces = ip_help.Assign(self.devices)

        # Build the device address table.
        assert self.devices.GetN() == self.interfaces.GetN()
        m = {}
        for i in xrange(0, self.interfaces.GetN()):
            m[self.interfaces.GetAddress(i).Get()] = self.devices.Get(i)
        self._address_map = m

# The full network topology for this simulation.
class topology:
    def __init__(self, lan_nodes=10, inet_nodes=10):
        # The core router between internet nodes, and the LAN.
        self.router = Node()

        # Create the internet model.
        self.inet = internet_model(self.router)

        for i in range(1, inet_nodes):
            self.inet.add_node(internet_node(self.inet.router, "10.1.%d.0" % i))

        # Create the LAN model
        self.lan = lan_model(self.router, lan_nodes)

        # Route everything everywhere to keep things simple.
        Ipv4GlobalRoutingHelper.PopulateRoutingTables()

    # Retrieves a device in the topology by address.
    def get_device_by_addr(self, address):
        # XXX: Ipv6 fail.
        if isinstance(address, str):
            address = Ipv4Address(address)

        # First try to find the device on the LAN.  This includes the
        # LAN address of the router.
        try:
            return self.lan._address_map[address.Get()]
        except KeyError:
            pass

        # Try to find the device on the Internet.  This will include all
        # point-to-point addresses of the router.
        try:
            return self.inet._address_map[address.Get()]
        except KeyError:
            pass

        return None

    def get_node_by_addr(self, address):
        dev = self.get_device_by_addr(address)
        if dev == None:
            return None

        return dev.GetNode()

    # XXX: improve to not log full lan, but only router.
    def router_enable_pcap(self):
        router_node_id = self.lan.devices.Get(0).GetNode().GetId()
        inet_helper = InternetStackHelper()
        inet_helper.EnablePcapIpv4("blaat", self.lan.interfaces)

def read_config(pathname):
    config = ConfigParser.ConfigParser()
    try:
        config.readfp(open(pathname))
    except IOError:
        print "Could not open '%s'.  In order to run this utility please\n" \
              "install '%s' to the current working directory." % \
                (pathname, pathname)
        sys.exit(1)

    for section in config.sections():
        yield dict(config.items(section))

# Manages TCP streams using scapy.
class scapy_stream:
    def __init__(self, packet):
        self.src = packet[IP].src
        self.sport = packet[TCP].sport
        self.dst = packet[IP].dst
        self.dport = packet[TCP].dport
        self.close_state = 0
        self.start_time = 0
        self.client_adus = []
        self.server_adus = []
        self.window_src = 0
        self.window_dst = 0
        self.address_map = {}
        self.container_name = ""

    def get_nat_dst_addr(self):
        # XXX: hack again, out of time though.  It works as a PoC, and if
        # there is any real interest in this we can do it nicely :-)
        if self.dst not in self.address_map:
            r = mixer.t.inet.random_address()
            self.address_map[self.dst] = str(r)

        return self.address_map[self.dst]

    def get_nat_dst_addr_port(self):
        return (self.get_nat_dst_addr(), self.dport)

    def get_nat_src_addr(self):
        if self.src not in self.address_map:
            r = mixer.t.inet.random_address()
            self.address_map[self.src] = str(r)

        return self.address_map[self.src]

    def get_nat_src_addr_port(self):
        return (self.get_nat_src_addr(), self.sport)

    def set_src_seq(self, seq):
        self.src_seq = seq

    def set_dst_seq(self, seq):
        self.dst_seq = seq

    # src -> dst : True, dst -> src : False
    def get_direction(self, packet):
        return packet[IP].src == self.src and packet[TCP].sport == self.sport

    @staticmethod
    def get_id(packet):
        return frozenset([(packet[IP].src, packet[TCP].sport),
                          (packet[IP].dst, packet[TCP].dport)])

# Scapy does not handle Ethernet trailers properly for packet[TCP].payload,
# so we calculate and slice the exact TCP payload here.  This should really
# have been done in the payload property...
def scapy_tcp_get_payload(packet):
    if IP not in packet or TCP not in packet:
        return ""

    l = packet[IP].len - packet[IP].ihl * 4 - packet[TCP].dataofs * 4
    return str(packet[TCP].payload)[0:l]

def streams_add(streams, packets, start_time):
    d = {}
    count = 0
    collisions = 0
    last_time = 0
    last_stream_id = None
    last_direction = None

    for packet in ifilter(lambda x: TCP in x, packets):
        stream_id = scapy_stream.get_id(packet)

        if packet[TCP].flags == 0x02:       # SYN
            # Check we haven't seen this stream.  This is probably a duplicate
            # SYN, but we really need to implement stream reassembly better...
            if stream_id in streams:
                sys.stderr.write('Warning: TCP stream already exists.\n')
                collisions += 1
                continue

            print "Created new TCP stream", stream_id
            count += 1
            s = scapy_stream(packet)
            s.set_src_seq(packet[TCP].seq)
            s.window_src = packet[TCP].window
            s.start_time = start_time
            s.client_adus.append(ADU_connect(s.dst, s.dport))
            streams[stream_id] = s

            # Push a stream ADU to the last seen stream, as this will be used
            # to create the current one.
            if last_stream_id:
                tdelta = packet.time - last_time

                last_s = streams[last_stream_id]
                if last_direction:
                    last_s.client_adus.append(ADU_stream(s, tdelta))
                else:
                    last_s.server_adus.append(ADU_stream(s, tdelta))
            else:
                streams['initial'] = s

        elif packet[TCP].flags == 0x12:     # SYN|ACK
            # Check if we've seen a SYN for this stream.
            if stream_id not in streams:
                continue

            # Ensure the SYN|ACK came from dst -> src.
            s = streams[stream_id]
            if s.get_direction(packet):
                sys.stderr.write('Fatal error: TCP wrong direction.\n')
                sys.exit(1)

            # record the dst seq.
            s.set_dst_seq(packet[TCP].seq)
            s.window_dst = packet[TCP].window
        elif packet[TCP].flags & 4:         # RST
            continue
        elif packet[TCP].flags & 0x10:      # ACK
            # Check if we've seen a SYN for this stream.
            if stream_id not in streams:
                continue

            s = streams[stream_id]
            if s.get_direction(packet):     # src -> dst
                if s.src_seq > packet[TCP].seq:
                    sys.stderr.write('Fatal error: Unexpected src seq ' +
                                     '(was %d, expected %d).\n' %
                                     (packet[TCP].seq, s.src_seq))
                    sys.exit(1)

                payload = scapy_tcp_get_payload(packet)

                s.src_seq = packet[TCP].seq
                tdelta = packet.time - last_time
                if payload and s.close_state & 1 == 0:
                    adu = ADU_send(scapy_tcp_get_payload(packet), tdelta)
                    s.client_adus.append(adu)
                    s.server_adus.append(ADU_recv(len(adu.data)))

                # Handle closes.
                if packet[TCP].flags & 1:   # FIN
                    s.client_adus.append(ADU_shutdown(tdelta))
                    if s.close_state == 2:
                        s.close_state |= 1
                    else:
                        s.close_state = 1
            else:
                payload = scapy_tcp_get_payload(packet)
                tdelta = packet.time - last_time

                if payload and s.close_state & 2 == 0:
                    adu = ADU_send(scapy_tcp_get_payload(packet), tdelta)
                    s.server_adus.append(adu)
                    s.client_adus.append(ADU_recv(len(adu.data)))

                if packet[TCP].flags & 1:   # FIN
                    s.server_adus.append(ADU_shutdown(tdelta))
                    if s.close_state == 1:
                        s.close_state |= 2
                    else:
                        s.close_state = 2
        else:
            sys.stderr.write('Fatal error: Unknown TCP flags %d\n' %
                             packet[TCP].flags)
            sys.exit(1)

        last_time = packet.time
        last_stream_id = stream_id
        last_direction = streams[stream_id].get_direction(packet)

    return (count, collisions)

class nids_mixer:
    def __init__(self):
        self.streams = []
        self.servers = {}
        self.count = 0

        # Enable checksum calculation in the protocols.  This leads to cleaner
        # results when viewing the generated PCAP in Wireshark.
        GlobalValue.Bind("ChecksumEnabled", BooleanValue(True))

        # Start out reading the config.
        for d in read_config("nids-mixer.cfg"):
            print "Processing", d['path']
            packets = rdpcap(d['path'])

            print "Start time:", d['start_time']
            print "Adding address mapping:", d['attacker_ip']
            print "Adding address mapping:", d['target_ip']

            pcap_streams = {}
            address_map = self.address_map_get(d)
            (c, c2) = streams_add(pcap_streams, packets, float(d['start_time']))
            print "Dissected %d TCP streams; %d collision pruned." % (c, c2)
            print "PCAP streams: %d." % len(pcap_streams)

            # Set the address map for all streams in this capture to the one
            # specified in the configuration.  Same for the name of the
            # container.
            for stream in pcap_streams.values():
                stream.address_map = address_map
                stream.container_name = d['name']

            self.streams.append(pcap_streams)

        # Create the topology, and the core router tracepoint.
        self.t = topology(inet_nodes=20)
        self.t.router_enable_pcap()

    def address_map_get(self, d):
        ak, av = d['attacker_ip'].split(' -> ')
        tk, tv = d['target_ip'].split(' -> ')

        return {ak: av, tk: tv}

    def start(self):
        for s in self.streams:
            # Check if we have a server bound for this address already.
            # If not, we create a new one, if so, we need to add the client
            # address to the ADU map on this server.
            server_address = s['initial'].get_nat_dst_addr_port()
            print "server addr:", server_address
            if server_address not in self.servers:
                mix_srv = mixer_server(self, s['initial'])
                mix_srv.node.AddApplication(mix_srv)
                self.servers[server_address] = mix_srv
            else:
                print "ADD:", s['initial'].container_name, s['initial'].src, s['initial'].sport
                print "MAP:", s['initial'].get_nat_src_addr()
                self.servers[server_address].add_stream(s['initial'])

            # We add one nanosecond to the start time, as the scheduler will
            # respond based on a heap of timers.  Doing this guarantees the
            # server application will always be started before the client
            # application.
            mix_client = mixer_client(self, s['initial'])
            t = Seconds(s['initial'].start_time) + NanoSeconds(1)
            mix_client.SetStartTime(t)
            mix_client.node.AddApplication(mix_client)

        Simulator.Run()
        Simulator.Destroy()

        # Post check for strange stuff.  There shouldn't be many ADUs left,
        # unless something is terribly wrong.  There are still some
        # circumstances in which there are ADUs left, so this isn't anything
        # big to worry about.
        for s in self.streams:
            for stream in s.values():
                if stream.client_adus:
                    print "CLIENT ADUS LEFT"
                    print "%s:%d <-> %s:%d" % (stream.src, stream.sport, stream.dst, stream.dport)
                    print "ADUS:", stream.client_adus

                if stream.server_adus:
                    print "SERVER ADUS LEFT"
                    print "%s:%d <-> %s:%d" % (stream.src, stream.sport, stream.dst, stream.dport)
                    print "ADUS:", stream.server_adus

mixer = nids_mixer()
mixer.start()
