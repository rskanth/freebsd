# Note: It is important to make sure you include the <bsd.kmod.mk> makefile after declaring the KMOD and SRCS variables.
.include <bsd.own.mk>
.PATH: ${.CURDIR}/../../../../dev/virtio/fs/9pfs

KMOD    =  virtio_fs

# Enumerate Source files for kernel module
SRCS+=  virtfs_subr.c
SRCS+=  virtfs_vfops.c
SRCS+=  virtfs_vnops.c
SRCS+=  vnode_if.h

#INC=-I/usr/share/mk/
# Include kernel module makefile
.include <bsd.kmod.mk>
