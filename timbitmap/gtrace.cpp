#define SHOW_THREAD_ID

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#ifdef WIN32
#include <winsock2.h>
#endif // WIN32
#ifdef __linux__
#include <arpa/inet.h>
#endif // __linux__

#ifdef SHOW_THREAD_ID
#include <pthread.h>
#endif // SHOW_THREAD_ID

#include "gtrace.h"

typedef struct {
	struct {
#ifdef __cplusplus
		bool configured{false};
		bool active{false};
#else
		bool configured;
		bool active;
#endif // __cplusplus
	} status;

	struct {
		bool enabled;
		int sock;
		struct sockaddr_in addr;
	} udp;

	//
	// stdout
	//
	struct {
		bool enabled;
	} so;

	//
	// file
	//
	struct {
		bool enabled;
		FILE* fp;
	} file;
} gtrace_t;

#ifdef __cplusplus
gtrace_t _gtrace;
#else
gtrace_t _gtrace = {
	.status.configured = false,
	.status.active = false
};
#endif

// ----------------------------------------------------------------------------
// api
// ----------------------------------------------------------------------------
void gtrace(const char* fmt, ...) {
	if (!_gtrace.status.configured) {
		_gtrace.status.configured = true;
		gtrace_open("127.0.0.1", 8908, true, NULL);
	}

	if (!_gtrace.status.active)
		return;

	int res;
	char buf[BUFSIZ];
	char* p = buf;
	int len = 0;
	int remn = BUFSIZ;

	struct timeval now;
	struct tm* local;
	gettimeofday(&now, NULL);
	local = localtime(&now.tv_sec);
	res = snprintf(p, remn, "%02d%02d%02d %02d%02d%02d-%03lu ",
	   (local->tm_year) % 100, local->tm_mon + 1, local->tm_mday,
	   local->tm_hour, local->tm_min, local->tm_sec, now.tv_usec / 1000);
	if (res < 0) return;
	p += res; len += res; remn -= res;	

#ifdef SHOW_THREAD_ID
	pthread_t id = pthread_self() & 0xFFFF;
	res = snprintf(p, remn, "%04lX ", id);
	if (res < 0) return;
	p += res; len += res; remn -= res;
#endif // SHOW_THREAD_ID

	va_list args;
	va_start(args, fmt);
	res = vsnprintf(p, remn, fmt, args);
	va_end(args);
	if (res < 0) return;
	p += res; len += res; // remn -= res;

	if (_gtrace.udp.enabled)
		sendto(_gtrace.udp.sock, buf, len, 0, (struct sockaddr*)&_gtrace.udp.addr, sizeof(struct sockaddr_in));

	if (_gtrace.so.enabled) {
		printf("%s", buf);
		fflush(stdout);
	}

	if (_gtrace.file.enabled) {
		fprintf(_gtrace.file.fp, "%s", buf);
		fflush(_gtrace.file.fp);
	}
}

bool gtrace_open(const char* ip, int port, bool so, const char* file) {
	_gtrace.status.configured = true;
	if (_gtrace.status.active)
		return false;

#ifdef WIN32
	static bool first = true;
	if (first) {
		WSADATA wsaData;
		WSAStartup(0x0202, &wsaData);
		first = false;
	}
#endif // WIN32

	//
	// udp
	//
	_gtrace.udp.enabled = false;
	if (ip != NULL && port != 0) {
		_gtrace.udp.sock = socket(AF_INET, SOCK_DGRAM, 0);
		if (_gtrace.udp.sock == -1) {
			fprintf(stderr, "socket return nullptr\n");
		} else {
			_gtrace.udp.addr.sin_family = AF_INET;
			_gtrace.udp.addr.sin_port = htons(port);
			_gtrace.udp.addr.sin_addr.s_addr = inet_addr(ip);
			memset(&_gtrace.udp.addr.sin_zero, 0, sizeof(_gtrace.udp.addr.sin_zero));
			_gtrace.udp.enabled = true;
		}
	}

	//
	// stdout
	//
	_gtrace.so.enabled = false;
	if (so == true) {
		_gtrace.so.enabled = true;
	}

	//
	// file
	//
	_gtrace.file.enabled = false;
	if (file != NULL) {
		_gtrace.file.fp = fopen(file, "a");
		if (_gtrace.file.fp == NULL) {
			fprintf(stderr, "fopen(%s) return nullptr\n", file);
		} else {
			_gtrace.file.enabled = true;
		}
	}

	_gtrace.status.active = true;
	return true;
}

bool gtrace_close(void) {
	_gtrace.status.configured = true;
	if (!_gtrace.status.active)
		return false;

	if (_gtrace.udp.enabled) {
		if (_gtrace.udp.sock != -1) {
			close(_gtrace.udp.sock);
			shutdown(_gtrace.udp.sock, 0x02); /* SD_BOTH */
			_gtrace.udp.sock = -1;
		}
	}

	if (_gtrace.so.enabled) {
	}

	if (_gtrace.file.enabled) {
		if (_gtrace.file.fp != NULL) {
			fclose(_gtrace.file.fp);
			_gtrace.file.fp = NULL;
		}
	}

	_gtrace.status.active = false;
	return true;
}

// ----------------------------------------------------------------------------
// macro
// ----------------------------------------------------------------------------
const char* gtrace_file_name(const char* file_name) {
#ifdef WIN32
	const char* p1 = strrchr(file_name, '\\');
	const char* p2 = strrchr(file_name, '/');
	const char* p	= p1 > p2 ? p1 : p2;
#endif // WIN32
#ifdef __linux__
	const char* p = strrchr(file_name, '/');
#endif // __linux__
	return (p == NULL ? file_name : p + 1);
}

const char* gtrace_func_name(const char* func_name) {
#ifdef WIN32
	const char* p = strrchr(func_name, ':');
	return (p == NULL ? func_name : p + 1);
#endif // WIN32
#ifdef __linux__
	return func_name;
#endif // __linux__
}
