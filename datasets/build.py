#!/usr/bin/python
#
# build.py
#
# Construct the NIDS evaluation database.
#
# -- Ronald Huizer / r.huizer@xs4all.nl (C) 2013
#
import os
import sys
import ConfigParser
from database import *

def read_config(pathname):
    config = ConfigParser.ConfigParser()
    try:
        config.readfp(open(pathname))
    except IOError:
        print "Could not open '%s'.  In order to run this utility please\n" \
              "install '%s' in the right location." % \
                (pathname, pathname)
        sys.exit(1)

    for section in config.sections():
        yield dict(config.items(section))

if len(sys.argv) < 2:
    sys.stderr.write("Use as: build.py <evaluation pcap>\n")
    sys.exit(1)

db = database('evaluation.db')
db.create()

for entry in read_config("../nids-mixer.cfg"):
    if entry['name'].startswith("BENIGN"):
        continue

    print entry['name'], entry['start_time']
    db.add_attack(entry['name'], entry['start_time'])

db.add_pcap(sys.argv[1])
