#include <cassert>

#include "config-host.h"
#include "Synchronization.h"

#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>

#include <semaphore.h>
#include <errno.h>
namespace dbaf {

struct SyncHeader{
    sem_t lock;
};


DBAFSynchronizedObjectInternal::DBAFSynchronizedObjectInternal(unsigned size) {
    m_size = size;
    m_headerSize = sizeof(SyncHeader);

    unsigned totalSize = m_headerSize + size;

    m_sharedBuffer = (uint8_t*)mmap(NULL, totalSize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
    if (!m_sharedBuffer) {
        perror("Could not allocate shared memory ");
        exit(-1);
    }

    SyncHeader *hdr = static_cast<SyncHeader*>((void*)m_sharedBuffer);

#ifdef CONFIG_DARWIN
    hdr->lock = 1;
#else
    if (sem_init(&hdr->lock, 1, 1) < 0) {
        perror("Could not initialize semaphore for shared memory region");
        exit(-1);
    }
#endif
}


DBAFSynchronizedObjectInternal::~DBAFSynchronizedObjectInternal()
{
    //SyncHeader *hdr = (SyncHeader*)m_sharedBuffer;

    //XXX: What about closing the semaphore, IPC?

    unsigned totalSize = m_headerSize + m_size;
    munmap(m_sharedBuffer, totalSize);
}

void *DBAFSynchronizedObjectInternal::acquire() {
    SyncHeader *hdr = (SyncHeader*)m_sharedBuffer;
#ifdef CONFIG_DARWIN
    while (__sync_lock_test_and_set(&hdr->lock, 0) != 0);
#else
    int ret;

     do {
        ret = sem_wait(&hdr->lock);
        if (ret < 0) {
            assert(errno != EDEADLK && errno != ENOSYS && errno != EINVAL);
        }
     }while(ret);

#endif
    return ((uint8_t*)m_sharedBuffer + m_headerSize);
}

void *DBAFSynchronizedObjectInternal::tryAquire()
{
    SyncHeader *hdr = (SyncHeader*)m_sharedBuffer;
#ifdef CONFIG_DARWIN
    if (__sync_lock_test_and_set(&hdr->lock, 0) != 0) {
        return NULL;
    }
#else
    int ret;

     do {
        ret = sem_trywait(&hdr->lock);
        if (ret < 0 && errno == EAGAIN) {
            return NULL;
        }
     }while(ret);

#endif
    return ((uint8_t*)m_sharedBuffer + m_headerSize);
}


void DBAFSynchronizedObjectInternal::release()
{
    SyncHeader *hdr = (SyncHeader*)m_sharedBuffer;
#ifdef CONFIG_DARWIN
    hdr->lock = 1;
#else
    if (sem_post(&hdr->lock) < 0) {
        assert(false && "Semaphore failed");
    }
#endif
}

uint64_t AtomicFunctions::read(uint64_t *address)
{
    return __sync_fetch_and_add(address, 0);
}

void AtomicFunctions::add(uint64_t *address, uint64_t value)
{
    __sync_fetch_and_add(address, value);
}

void AtomicFunctions::sub(uint64_t *address, uint64_t value)
{
    __sync_fetch_and_sub(address, value);
}

void AtomicFunctions::write(uint64_t *address, uint64_t value)
{
    *address = value;
}
}
