AM_CXXFLAGS = $(WARNING_CXXFLAGS) $(PICKY_CXXFLAGS) $(HARDEN_CFLAGS) $(MISC_CXXFLAGS) $(CODE_COVERAGE_CXXFLAGS) $(FUZZING_CFLAGS)

if ENABLE_FUZZING
  noinst_PROGRAMS = terminal_parser_fuzzer terminal_fuzzer \
    forward_frame_fuzzer tcpinudp_fuzzer udp_forward_fuzzer tcp_adapter_fuzzer file_copy_fuzzer punch_fuzzer
endif

terminal_parser_fuzzer_CPPFLAGS = -I$(top_srcdir)/
terminal_parser_fuzzer_LDADD = ../terminal/libmoshterminal.a ../util/libmoshutil.a
terminal_parser_fuzzer_SOURCES = terminal_parser_fuzzer.cc

terminal_fuzzer_CPPFLAGS = -I$(top_srcdir)/
terminal_fuzzer_LDADD = ../terminal/libmoshterminal.a ../util/libmoshutil.a ../statesync/libmoshstatesync.a ../protobufs/libmoshprotos.a $(TINFO_LIBS) $(protobuf_LIBS)
terminal_fuzzer_SOURCES = terminal_fuzzer.cc

# Port forwarding.  See forward_fuzz.h for the shape of their input.
FORWARD_LDADD = ../network/libmoshnetwork.a ../crypto/libmoshcrypto.a ../util/libmoshutil.a $(CRYPTO_LIBS)

forward_frame_fuzzer_CPPFLAGS = -I$(top_srcdir)/ -I$(top_builddir)/
forward_frame_fuzzer_LDADD = $(FORWARD_LDADD)
forward_frame_fuzzer_SOURCES = forward_frame_fuzzer.cc forward_fuzz.h

tcpinudp_fuzzer_CPPFLAGS = -I$(top_srcdir)/ -I$(top_builddir)/
tcpinudp_fuzzer_LDADD = $(FORWARD_LDADD)
tcpinudp_fuzzer_SOURCES = tcpinudp_fuzzer.cc forward_fuzz.h

udp_forward_fuzzer_CPPFLAGS = -I$(top_srcdir)/ -I$(top_builddir)/
udp_forward_fuzzer_LDADD = $(FORWARD_LDADD)
udp_forward_fuzzer_SOURCES = udp_forward_fuzzer.cc forward_fuzz.h

tcp_adapter_fuzzer_CPPFLAGS = -I$(top_srcdir)/ -I$(top_builddir)/
tcp_adapter_fuzzer_LDADD = $(FORWARD_LDADD)
tcp_adapter_fuzzer_SOURCES = tcp_adapter_fuzzer.cc forward_fuzz.h

file_copy_fuzzer_CPPFLAGS = -I$(top_srcdir)/ -I$(top_builddir)/
file_copy_fuzzer_LDADD = $(FORWARD_LDADD)
file_copy_fuzzer_SOURCES = file_copy_fuzzer.cc

punch_fuzzer_CPPFLAGS = -I$(top_srcdir)/ -I$(top_builddir)/
punch_fuzzer_LDADD = $(FORWARD_LDADD)
punch_fuzzer_SOURCES = punch_fuzzer.cc
