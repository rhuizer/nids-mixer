nids-mixer
==========

A NS3 based TCP stream mixer for NIDS dataset generation.

0. Notes and comments
=====================

  Not all datasets have been used in the generated database.  In fact, we have
  focused most of our efforts on making sure the NIDS mixer software behaves
  more or less as expected.

  The evaluation database we have constructed is a simple 5 minute HTTP
  browsing session that has some attacks to other network nodes interleaved.
  As such it is not representative of a real NIDS evaluation dataset, but we
  believe our project provides a good starting point for creating a nids-mixer
  configuration that leads to more natural results.

1. Running nids-mixer.py
========================

  In order to reproduce the results obtained, it is necessary to install NS-3,
  which can be downloaded from http://www.nsnam.org

  The version we used is 3.17, and we suggest this version is used in order to
  apply the patches to the system that were necessary for nids-mixer to function
  properly.

  The following instructions should work on most generic Linux versions when
  ran from the current directory.

2. Quick installation
=====================

  wget https://www.nsnam.org/release/ns-allinone-3.17.tar.bz2
  tar -jxvf ns-allinone-3.17.tar.bz2
  cd ns-allinone-3.17/ns-3.17/
  ./waf configure --enable-examples --enable-tests
  # Please ensure "Python Bindings" is set to "enabled" at this point.
  # If not, you will have to install the necessary dependencies yourself.
  ./waf
  # Ugly way to add some python bindings.  No time learn pybindgen right now.
  cp -f ../../ns3-patches/ns3module.cc build/src/network/bindings/
  cp -f ../../ns3-patches/tcp-socket-base.cc src/internet/model/
  cp -f ../../ns3-patches/tcp-socket-base.h src/internet/model/
  rm -f build/src/network/bindings/ns3module.cc.7.o
  rm -f build/bindings/python/ns/network.so
  ./waf
  # Install the software.
  cp ../../nids-mixer.py .

  # WARNING -- IMPORTANT -- WARNING
  # Change the the 'root' attribute in the 'DEFAULT' section to the dataset path.
  cp ../../nids-mixer.cfg .

  # Run everything
  ./waf --pyrun nids-mixer.py
  # The final .pcap file will be named "blaat-n0-*.pcap"

3. Files
========

datasets/		Directory containing the core datasets.  These datasets
			have been removed from this project.  You should
                        compile your own.
  build.py		  Python executable to build the evualuation database.
  database.py	 	  Python module that contains database code.

doc/			Documentation of the project
  exam.lyx		  Source code to our paper.
  exam.pdf		  The paper to the project.
  refs/			  Non-exhaustive collection of papers referenced.

ns3-patches/		Patches that must be applied to NS-3 to use the project.
  ns3module.cc		  Patch to the generated network python bindings.
  tcp-socket-base.cc	  Patch to TcpSocketBase to add functionality.
  tcp-socket-base.h	  Patch to TcpSocketBase to add functionality.

nids-mixer.cfg		Configuration file for our NS-3 traffic mixer.
nids-mixer.py		Source code for our NS-3 traffic mixer.
README.TXT		See this file.

  -- Ronald Huizer / r.huizer@xs4all.nl (c) 2013
