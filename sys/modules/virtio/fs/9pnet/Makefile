# Note: It is important to make sure you include the <bsd.kmod.mk> makefile after declaring the KMOD and SRCS variables.
.include <bsd.own.mk>
.PATH: ${.CURDIR}/../../../../dev/virtio/fs/9pnet

KMOD    =  9ptrans

# Enumerate Source files for kernel module
SRCS    =  device_if.h bus_if.h opt_cam.h trans_virtio.c client.c protocol.c

#INC=-I/usr/share/mk/
# Include kernel module makefile
.include <bsd.kmod.mk>
