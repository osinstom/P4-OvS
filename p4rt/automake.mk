lib_LTLIBRARIES += p4rt/libp4rt.la

p4rt_libp4rt_la_LDFLAGS = \
        $(OVS_LTINFO) \
        -Wl,--version-script=$(top_builddir)/p4rt/libp4rt.sym \
        $(AM_LDFLAGS)

p4rt_libp4rt_la_SOURCES = \
    p4rt/p4rt-dpif.c \
    p4rt/p4rt-dpif.h \
    p4rt/p4rt-provider.h \
    p4rt/p4rt.c \
    p4rt/p4rt.h \
    p4rt/p4rt-switch.h

p4rt_libp4rt_la_LIBADD = \
PI/libpi.la

p4rt_libp4rt_la_CPPFLAGS = $(AM_CPPFLAGS)
p4rt_libp4rt_la_CFLAGS = $(AM_CFLAGS)

p4rt_libp4rt_la_LIBADD += \
-lpifeproto -lpigrpcserver -lpi -lpip4info -lgrpc -lprotobuf

pkgconfig_DATA += \
	p4rt/libp4rt.pc
