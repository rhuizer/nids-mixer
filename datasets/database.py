# database.py
#
# A database to store .pcap packet traces for NIDS evaluation, which allows
# for annotation of malicious packets, such that they can be differentiated
# from benign packets.
#
# -- Ronald Huizer / r.huizer@xs4all.nl (C) 2013
import os
import socket
import sqlite3
import struct
from scapy.all import *

class database:
    def __init__(self, filename):
        open(filename, 'w').close()
        self.conn = sqlite3.connect(filename)

    def create(self):
        c = self.conn.cursor()

        # Table of attacks, each of which consists of one or more packets.
        c.execute(
            "CREATE TABLE Attack ("
                "Id             INTEGER     PRIMARY KEY AUTOINCREMENT,"
                "Name           TEXT        NOT NULL,"
                "Timestamp      DOUBLE      NOT NULL"
            ")"
        )

        # Table relating an ordered list of packets to an attack.
        # This can be used when we can perform taint propagation in NS-3
        # to correlate malicious ADUs to generated packets.  Currently it
        # is unused.
        c.execute(
            "CREATE TABLE AttackPackets ("
                "AttackId       INTEGER     NOT NULL,"
                "PacketId       INTEGER     NOT NULL,"
                "Ordering       INTEGER     NOT NULL,"
                "FOREIGN KEY(AttackId) REFERENCES Attack(Id),"
                "FOREIGN KEY(PacketId) REFERENCES Packet(Id),"
                "PRIMARY KEY(AttackId, PacketId, Ordering)"
            ")"
        )

        # Table containing all the packets in this database, in order of
        # arrival.  Although Packet.Timestamp could be used for this,
        # later we might want to augment the database with other streams
        # than just the evaluation one, so we use this already.
        c.execute(
            "CREATE TABLE Packets ("
                "PacketId       INTEGER     NOT NULL,"
                "Ordering       INTEGER     NOT NULL,"
                "FOREIGN KEY(PacketId) REFERENCES Packet(Id),"
                "PRIMARY KEY(PacketId, Ordering)"
            ")"
        )

        c.execute(
            "CREATE TABLE Packet ("
                "Id             INTEGER     PRIMARY KEY AUTOINCREMENT,"
                "Timestamp      INTEGER     NOT NULL,"
                "RawData        BLOB        NOT NULL"
            ")"
        )

        c.execute(
            "CREATE TABLE Header ("
                "Id             INTEGER     PRIMARY KEY AUTOINCREMENT,"
                "Type           TEXT        NOT NULL"
            ")"
        )

        c.execute(
            "CREATE TABLE PacketHeaders ("
                "PacketId       INTEGER NOT NULL,"
                "HeaderId       INTEGER NOT NULL,"
                "Ordering       INTEGER NOT NULL,"
                "FOREIGN KEY(PacketId) REFERENCES Packet(Id),"
                "FOREIGN KEY(HeaderId) REFERENCES Header(Id),"
                "PRIMARY KEY(PacketId, HeaderId, Ordering)"
            ")"
        )

        c.execute(
            "CREATE TABLE IpHeader ("
                "Id              INTEGER      NOT NULL,"
                "Version         TINYINT      NOT NULL,"
                "IHL             TINYINT      NOT NULL,"
                "DSCP            TINYINT      NOT NULL,"
                "ECN             TINYINT      NOT NULL,"
                "Length          SMALLINT     NOT NULL,"
                "Identification  SMALLINT     NOT NULL,"
                "Flags           TINYINT      NOT NULL,"
                "FragmentOffset  SMALLINT     NOT NULL,"
                "TimeToLive      TINYINT      NOT NULL,"
                "Protocol        TINYINT      NOT NULL,"
                "Checksum        SMALLINT     NOT NULL,"
                "SourceIP        INT          NOT NULL,"
                "DestIP          INT          NOT NULL,"
                "FOREIGN KEY(Id) REFERENCES Header(Id)"
            ")"
        )

        c.execute(
            "CREATE TABLE TcpHeader ("
                "Id                 INT         NOT NULL,"
                "SourcePort         SMALLINT    NOT NULL,"
                "DestPort           SMALLINT    NOT NULL,"
                "Seq                INT         NOT NULL,"
                "Ack                INT         NOT NULL,"
                "Offset             TINYINT     NOT NULL,"
                "Flags              TINYINT     NOT NULL,"
                "Window             SMALLINT    NOT NULL,"
                "Checksum           SMALLINT    NOT NULL,"
                "UrgentPtr          SMALLINT    NOT NULL,"
                "FOREIGN KEY(Id) REFERENCES Header(Id)"
            ")"
        )

        c.execute(
            "CREATE TABLE UdpHeader ("
                "Id             INTEGER         NOT NULL,"
                "SourcePort     SMALLINT        NOT NULL,"
                "DestPort       SMALLINT        NOT NULL,"
                "Length         SMALLINT        NOT NULL,"
                "Checksum       SMALLINT        NOT NULL,"
                "FOREIGN KEY(Id) REFERENCES Header(Id)"
            ")"
        )

        self.conn.commit()

    def add_attack(self, name, timestamp):
        c = self.conn.cursor()
        c.execute("INSERT INTO Attack VALUES (?,?,?)", (None, name, timestamp))
        self.conn.commit()

    def add_pcap(self, pcap_pathname):
        c = self.conn.cursor()

        print "[+] Processing", pcap_pathname
        packets = rdpcap(pcap_pathname)

        order = 0
        for packet in packets:
            if order % 100 == 0:
                sys.stdout.write("\r[%d/%d]" % (order, len(packets)))
                sys.stdout.flush()

            if not self.add_packet(c, packet):
                continue

            c.execute("INSERT INTO Packets VALUES (?,?)", (c.lastrowid, order))
            order += 1

        self.conn.commit()

    def add_packet(self, c, pkt):
        start_layer = None
        header_ids = []

        # Process IP packets.  We only handle IPv4 for now, so we only
        # process ICMP/UDP/TCP when embedded in IP packets.
        if IP in pkt:
            start_layer = pkt[IP]
            self.add_ip_header(c, pkt[IP])
            header_ids.append(c.lastrowid)

            if UDP in pkt:
                self.add_udp_header(c, pkt[UDP])
                header_ids.append(c.lastrowid)
            elif TCP in pkt:
                self.add_tcp_header(c, pkt[TCP])
                header_ids.append(c.lastrowid)

        # If the list is empty, we're not interested in this packet.
        if not header_ids:
            return False

        c.execute("INSERT INTO Packet VALUES (?,?,?)",
            (None, pkt.time, sqlite3.Binary(str(start_layer))))
        packet_id = c.lastrowid

        for depth, header_id in enumerate(header_ids):
            c.execute("INSERT INTO PacketHeaders VALUES (?,?,?)",
                (packet_id, header_id, depth))

        return True

    def add_ip_header(self, c, ip):
        src = struct.unpack("!I", socket.inet_aton(ip.src))[0]
        dst = struct.unpack("!I", socket.inet_aton(ip.dst))[0]

        c.execute("INSERT INTO Header VALUES (?,?)", (None, "IpHeader"))

        c.execute("INSERT INTO IpHeader VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (c.lastrowid, ip.version, ip.ihl, ip.tos >> 2, ip.tos & 3, ip.len,
             ip.id, ip.flags, ip.frag, ip.ttl, ip.proto, ip.chksum, src, dst))

    def add_tcp_header(self, c, tcp):
        c.execute("INSERT INTO Header VALUES (?,?)", (None, "TcpHeader"))

        c.execute("INSERT INTO TcpHeader VALUES (?,?,?,?,?,?,?,?,?,?)",
            (c.lastrowid, tcp.sport, tcp.dport, tcp.seq, tcp.ack, tcp.dataofs,
             tcp.flags, tcp.window, tcp.chksum, tcp.urgptr))

    def add_udp_header(self, c, udp):
        c.execute("INSERT INTO Header VALUES (?,?)", (None, "UdpHeader"))

        c.execute("INSERT INTO UdpHeader VALUES (?,?,?,?,?)",
            (c.lastrowid, udp.sport, udp.dport, udp.len, udp.chksum))
