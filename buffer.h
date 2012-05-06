#ifndef BUFFER_H
#define BUFFER_H

#include <queue>
#include <pthread.h>

using namespace std;

class buffer
{
//Disclaimer: This is not supposed to be optimal
//This is supposed to *work*
private:
    queue<unsigned char> data;
    pthread_mutex_t mutex;
public:
    buffer();
    ~buffer();
    void lock();
    void unlock();
    void add(char c);
    void add(const char *s);
    void lockedAdd(char c);
    void lockedAdd(const char *s);
    int lockedSize();
    unsigned char get();
    unsigned char lockedGet();
};

#endif
