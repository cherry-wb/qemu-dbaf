/*
 * QEMU host block devices
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 */

#ifndef BLOCKDEV_H
#define BLOCKDEV_H

#include "block/block.h"
#include "qapi/error.h"
#include "qemu/queue.h"
#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

extern void blockdev_mark_auto_del(BlockDriverState *bs);
extern void blockdev_auto_del(BlockDriverState *bs);

typedef enum {
    IF_DEFAULT = -1,            /* for use with drive_add() only */
    /*
     * IF_IDE must be zero, because we want QEMUMachine member
     * block_default_type to default-initialize to IF_IDE
     */
    IF_IDE = 0,
    IF_NONE,
    IF_SCSI, IF_FLOPPY, IF_PFLASH, IF_MTD, IF_SD, IF_VIRTIO, IF_XEN,
    IF_COUNT
} BlockInterfaceType;

struct DriveInfo {
    BlockDriverState *bdrv;
    char *id;
    const char *devaddr;
    BlockInterfaceType type;
    int bus;
    int unit;
    int auto_del;               /* see blockdev_mark_auto_del() */
    bool enable_auto_del; /* Only for legacy drive_init() */
    int media_cd;
    int cyls, heads, secs, trans;
    QemuOpts *opts;
    char *serial;
    QTAILQ_ENTRY(DriveInfo) next;
    int refcount;
};

extern DriveInfo *drive_get(BlockInterfaceType type, int bus, int unit);
extern DriveInfo *drive_get_by_index(BlockInterfaceType type, int index);
extern int drive_get_max_bus(BlockInterfaceType type);
extern DriveInfo *drive_get_next(BlockInterfaceType type);
extern void drive_get_ref(DriveInfo *dinfo);
extern void drive_put_ref(DriveInfo *dinfo);
extern DriveInfo *drive_get_by_blockdev(BlockDriverState *bs);

extern QemuOpts *drive_def(const char *optstr);
extern QemuOpts *drive_add(BlockInterfaceType type, int index, const char *file,
                    const char *optstr);
extern DriveInfo *drive_init(QemuOpts *arg, BlockInterfaceType block_default_type);

/* device-hotplug */

extern DriveInfo *add_init_drive(const char *opts);

extern void qmp_change_blockdev(const char *device, const char *filename,
                         const char *format, Error **errp);
extern void do_commit(Monitor *mon, const QDict *qdict);
extern int do_drive_del(Monitor *mon, const QDict *qdict, QObject **ret_data);
#ifdef __cplusplus
}
#endif // __cplusplus
#endif
