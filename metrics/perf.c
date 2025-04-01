// Perf
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

#define PERF_EVENT_ATTR_SIZE sizeof(struct perf_event_attr)


// Function to create and configure a perf_event
int create_perf_event()
{
	struct perf_event_attr attr;
	memset(&attr, 0, PERF_EVENT_ATTR_SIZE);

	// Set the event type to count instructions
	attr.type = PERF_TYPE_HARDWARE;
	attr.config = PERF_COUNT_HW_INSTRUCTIONS;

	// Set the event for the current CPU
	attr.size = PERF_EVENT_ATTR_SIZE;
	attr.disabled = 1; // We disable the event initially

	// Open the event (this uses the /dev/perf_event interface)
	int fd = syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);

	if (fd == -1)
	{
		perror("perf_event_open");
		return -1;
	}

	return fd;
}

// Function to start counting
void start_counter(int fd)
{
	ioctl(fd, PERF_EVENT_IOC_RESET, 0);	 // Reset the counter
	ioctl(fd, PERF_EVENT_IOC_ENABLE, 0); // Enable the event
}

// Function to read the counter value
long long read_counter(int fd)
{
	long long count;
	if (read(fd, &count, sizeof(count)) == -1)
	{
		perror("read");
		return -1;
	}
	return count;
}

// Function to stop counting and get the result
long long stop_counter(int fd)
{
	ioctl(fd, PERF_EVENT_IOC_DISABLE, 0); // Disable the event
	return read_counter(fd);
}

