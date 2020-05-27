lib_LTLIBRARIES += PI/libpi.la

PI_libpi_la_LDFLAGS = \
        $(OVS_LTINFO) \
        $(AM_LDFLAGS)

PI_libpi_la_SOURCES = \
PI/pi_imp.c \
PI/pi_learn_imp.c \
PI/pi_act_prof.c \
PI/pi_counter_imp.c \
PI/pi_tables_imp.c \
PI/pi_clone.c \
PI/pi_mc.c \
PI/pi_meter.c