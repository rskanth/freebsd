/*-
 * Plan9 filesystem (9P2000.u) subroutines.  This file is intended primarily
 * for Plan9-specific details.
 * This file consists of all the Non VFS Subroutines.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/uio.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/limits.h>
#include <sys/vnode.h>

#include "virtfs_proto.h"
#include "../client.h"
#include "../protocol.h"
#include "../9p.h"
#include "virtfs.h"

int p9_debug_level = 0xFFFF;
int
virtfs_proto_dotl(struct virtfs_session *vses)
{
    return (vses->flags & VIRTFS_PROTO_2000L);
}

struct p9_fid *
virtfs_init_session(struct mount *mp)
{
    struct p9_fid *fid;
    struct virtfs_session *vses;
    struct virtfs_mount *virtmp;

    virtmp = mp->mnt_data;
    vses = &virtmp->virtfs_session;
    vses->uid = 0;

    vses->clnt = p9_client_create(mp);

    if (vses->clnt == NULL) {
        p9_debug(SUBR, "problem initializing 9p client\n");
        goto fail;
    }
    /* Find the client version and cache the copy. We will use this copy 
     * throughout FS layer.*/
    if (p9_is_proto_dotl(vses->clnt)) {
        vses->flags |= VIRTFS_PROTO_2000L;

    } else if (p9_is_proto_dotu(vses->clnt)) {
        vses->flags |= VIRTFS_PROTO_2000U;
    }

    /* Attach with the backend host*/
    fid = p9_client_attach(vses->clnt);

    if (fid == NULL) {

        p9_debug(SUBR, "cannot attach\n");
        goto fail;
    }
    p9_debug(SUBR, "Attach successful fid :%p\n",fid);

    fid->uid = vses->uid;
    p9_debug(SUBR, "INIT session successful\n");

    return fid;

fail:

   if (vses->clnt)
	p9_client_destroy(vses->clnt);

   return NULL;
}

/* Call from unmount. Close the session. */
void
virtfs_close_session(struct mount *mp)
{
	struct virtfs_session *vses;
	struct virtfs_mount *vmp;

  	vmp = VFSTOP9(mp);
    	vses = &vmp->virtfs_session;

	/* Do the reverse of the init session  */
	/* Detach the root fid.*/
	p9_client_detach(vses->rnp.vfid);
	/* Clean up the clnt structure. */
	p9_client_destroy(vses->clnt);
	p9_debug(SUBR, " Clean close session .\n");
}
