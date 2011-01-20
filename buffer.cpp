
#include "buffer.h"
#include <pthread.h>
buffer::buffer()
{
	mutex = new pthread_mutex_t;
	pthread_mutex_init(mutex, NULL);
}

buffer::~buffer()
{
	if(mutex)
		delete mutex;
}

void buffer::lock()
{
	pthread_mutex_lock(mutex);
}

void buffer::unlock()
{
	pthread_mutex_unlock(mutex);
}

void buffer::add(char c) {data.push(c);}
void buffer::add(const char *s)
{
	for(const char *p = s; *p; p++)
		data.push(*p);
}

void buffer::lockedAdd(char c)
{
	lock();
	add(c);
	unlock();
}

void buffer::lockedAdd(const char *s)
{
	lock();
	add(s);
	unlock();
}

int buffer::lockedSize()
{
	lock();
	int retval = data.size();
	unlock();
	return retval;
}

unsigned char buffer::get()
{
	unsigned char c = data.front();
	data.pop();
	return c;
}

unsigned char buffer::lockedGet()
{
	lock();
	unsigned char retval = get();
	unlock();
return retval;
}
