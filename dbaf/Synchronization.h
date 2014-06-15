#ifndef DBAF_SYNCHRONIZATION_H
#define DBAF_SYNCHRONIZATION_H

#include <inttypes.h>
#include <string>

namespace dbaf {

class DBAFSynchronizedObjectInternal {
private:
    uint8_t *m_sharedBuffer;
    unsigned m_size;
    unsigned m_headerSize;
public:
    DBAFSynchronizedObjectInternal(){ }
    DBAFSynchronizedObjectInternal(unsigned size);
    ~DBAFSynchronizedObjectInternal();

    void lock();
    void release();
    void *acquire();
    void *tryAquire();

    //Unsynchronized function to get the buffer
    void *get() const {
        return ((uint8_t*)m_sharedBuffer)+m_headerSize;
    }
};

/**
 *  This class creates a shared memory buffer on which
 *  all DBAF processes can perform read/write requests.
 */
template <class T>
class DBAFSynchronizedObject {
private:
    DBAFSynchronizedObjectInternal sync;


public:

    DBAFSynchronizedObject():sync(DBAFSynchronizedObjectInternal(sizeof(T))) {
        new (sync.get()) T();
    }

    ~DBAFSynchronizedObject() {
        T* t = (T*)sync.get();
        t->~T();
    }

    T *acquire() {
        return (T*)sync.acquire();
    }

    //Returns null if could not lock the object
    T *tryAcquire() {
        return (T*)sync.tryAquire();
    }

    void release() {
        sync.release();
    }

    T* get() const {
        return (T*)sync.get();
    }

};

class AtomicFunctions {
public:
    static uint64_t read(uint64_t *address);
    static void write(uint64_t *address, uint64_t value);
    static void add(uint64_t *address, uint64_t value);
    static void sub(uint64_t *address, uint64_t value);
};

template <class T>
class AtomicObject {
private:
    mutable uint64_t m_value;

public:
    AtomicObject() {}

    T read() const{
        uint64_t value = AtomicFunctions::read(&m_value);
        return *(T*)&value;
    }

    void write(T &object) {
        AtomicFunctions::write(&m_value, *(uint64_t*)&object);
    }
};

}

#endif
