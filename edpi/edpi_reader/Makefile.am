bin_PROGRAMS = edpi_reader

AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_srcdir)/src/lib/third_party/include @PCAP_INC@ @HS_INC@
AM_CFLAGS = @PTHREAD_CFLAGS@ # --coverage

LDADD = $(top_builddir)/src/lib/libndpi.la @JSON_C_LIB@ @PTHREAD_LIBS@ @PCAP_LIB@ @DL_LIB@ @HS_LIB@ -lm
AM_LDFLAGS = -static @DL_LIB@ @HS_LIB@

edpi_reader_SOURCES = edpi_reader.c ndpi_util.c ndpi_util.h uthash.h pipe.c pipe.h

edpi_reader.o: edpi_reader.c

