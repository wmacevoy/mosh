AM_CPPFLAGS = -I$(top_srcdir)/ $(protobuf_CFLAGS)
AM_CXXFLAGS = $(WARNING_CXXFLAGS) $(PICKY_CXXFLAGS) $(HARDEN_CFLAGS) $(MISC_CXXFLAGS) $(CODE_COVERAGE_CXXFLAGS)

noinst_LIBRARIES = libmoshnetwork.a

libmoshnetwork_a_SOURCES = network.cc network.h networktransport-impl.h networktransport.h punch.cc punch.h transportfragment.cc transportfragment.h transportsender-impl.h transportsender.h transportstate.h compressor.cc compressor.h filecopy.cc filecopy.h forwarding.h relay.cc relay.h sidechannel.h streamchild.cc streamchild.h tcpadapter.cc tcpadapter.h tcpforward.cc tcpforward.h tcpinudp.cc tcpinudp.h udpforward.cc udpforward.h
