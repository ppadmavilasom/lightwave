
lib_LTLIBRARIES = libvmafdclient.la

idl_srcdir=$(top_srcdir)/vmafd/idl

libvmafdclient_la_CPPFLAGS = \
    -I$(top_srcdir)/vmafd/include \
    -I$(top_srcdir)/vmafd/include/public \
    -I$(top_srcdir)/vmidentity/ssoclients/common/include/public \
    -I$(top_srcdir)/vmidentity/ssoclients/oidc/include/public \
    -I$(top_srcdir)/vmcommon/include/public \
    @DCERPC_INCLUDES@ \
    @LW_INCLUDES@ \
    @OPENSSL_INCLUDES@

libvmafdclient_la_SOURCES = \
    afdlocalclient.c \
    authtoken.c \
    binding.c \
    cdcclient.c\
    cdclocalclient.c\
    client.c \
    globals.c \
    libmain.c \
    oidctoafderror.c \
    rpc.c \
    slclient.c \
    vmafd_cstub.c \
    vmafdsuperlog_cstub.c \
    vecs.c \
    vecsclient.c \
    vecslocalclient.c

libvmafdclient_la_LIBADD = \
    $(top_builddir)/vmcommon/libvmcommon.la \
    @top_builddir@/vmafd/common/libcommon.la \
    @top_builddir@/vmidentity/ssoclients/common/src/libssocommon.la \
    @top_builddir@/vmidentity/ssoclients/oidc/src/libssooidc.la \
    @DCERPC_LIBS@ \
    @LWBASE_LIBS@ \
    @GSSAPI_LIBS@ \
    @PTHREAD_LIBS@

libvmafdclient_la_LDFLAGS = \
    @DCERPC_LDFLAGS@ \
    @LW_LDFLAGS@

CLEANFILES = \
    vmafd_h.h \
    vmafd_cstub.c \
    vmafd_sstub.c \
    vmafdsuperlog_h.h \
    vmafdsuperlog_cstub.c \
    vmafdsuperlog_sstub.c

BUILT_SOURCES = vmafd_h.h \
                vmafdsuperlog_h.h

vmafd_h.h vmafd_cstub.c: $(idl_srcdir)/vmafd.idl
	$(IDL) $(IDLFLAGS) -keep c_source -header vmafd_h.h -sstub_pref Srv_ -I$(idl_srcdir) -I$(top_srcdir)/vmafd/include/public $<

vmafdsuperlog_h.h vmafdsuperlog_cstub.c: $(idl_srcdir)/vmafdsuperlog.idl
	$(IDL) $(IDLFLAGS) -keep c_source -header vmafdsuperlog_h.h -sstub_pref Srv_ -I$(idl_srcdir) -I$(top_srcdir)/vmafd/include/public $<
