#ifndef PLATFORM_H
#define PLATFORM_H

/* Cross-platform socket and threading abstractions */

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>

    #pragma comment(lib, "ws2_32.lib")

    typedef SOCKET socket_t;
    typedef HANDLE thread_t;
    typedef HANDLE mutex_t;
    typedef CRITICAL_SECTION mutex_native_t;

    #define INVALID_SOCKET_VALUE INVALID_SOCKET
    #define SOCKET_ERROR_VALUE SOCKET_ERROR
    #define WOULD_BLOCK WSAEWOULDBLOCK
    #define IN_PROGRESS WSAEINPROGRESS
    #define ALREADY_CONNECTED WSAEISCONN

    #define socket_close closesocket
    #define socket_errno WSAGetLastError()
    #define socket_would_block(err) ((err) == WSAEWOULDBLOCK)

    static inline int platform_init(void) {
        WSADATA wsa;
        return WSAStartup(MAKEWORD(2, 2), &wsa);
    }

    static inline void platform_cleanup(void) {
        WSACleanup();
    }

    static inline int socket_set_nonblocking(socket_t sock) {
        u_long mode = 1;
        return ioctlsocket(sock, FIONBIO, &mode);
    }

    static inline int socket_set_blocking(socket_t sock) {
        u_long mode = 0;
        return ioctlsocket(sock, FIONBIO, &mode);
    }

    /* Thread functions */
    typedef DWORD (WINAPI *thread_func_t)(void*);

    static inline int thread_create(thread_t* thread, thread_func_t func, void* arg) {
        *thread = CreateThread(NULL, 0, func, arg, 0, NULL);
        return (*thread == NULL) ? -1 : 0;
    }

    static inline int thread_join(thread_t thread) {
        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
        return 0;
    }

    static inline int thread_detach(thread_t thread) {
        CloseHandle(thread);
        return 0;
    }

    /* Mutex functions */
    static inline int mutex_init(mutex_t* mutex) {
        mutex_native_t* cs = (mutex_native_t*)malloc(sizeof(mutex_native_t));
        if (!cs) return -1;
        InitializeCriticalSection(cs);
        *mutex = (HANDLE)cs;
        return 0;
    }

    static inline int mutex_lock(mutex_t* mutex) {
        EnterCriticalSection((mutex_native_t*)*mutex);
        return 0;
    }

    static inline int mutex_trylock(mutex_t* mutex) {
        return TryEnterCriticalSection((mutex_native_t*)*mutex) ? 0 : -1;
    }

    static inline int mutex_unlock(mutex_t* mutex) {
        LeaveCriticalSection((mutex_native_t*)*mutex);
        return 0;
    }

    static inline int mutex_destroy(mutex_t* mutex) {
        DeleteCriticalSection((mutex_native_t*)*mutex);
        free((mutex_native_t*)*mutex);
        return 0;
    }

    static inline void platform_sleep_ms(int ms) {
        Sleep(ms);
    }

#else /* POSIX (Linux, etc.) */
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
    #include <pthread.h>

    typedef int socket_t;
    typedef pthread_t thread_t;
    typedef pthread_mutex_t mutex_t;

    #define INVALID_SOCKET_VALUE (-1)
    #define SOCKET_ERROR_VALUE (-1)
    #define WOULD_BLOCK EWOULDBLOCK
    #define IN_PROGRESS EINPROGRESS
    #define ALREADY_CONNECTED EISCONN

    #define socket_close close
    #define socket_errno errno
    #define socket_would_block(err) ((err) == EWOULDBLOCK || (err) == EAGAIN)

    static inline int platform_init(void) {
        return 0; /* No initialization needed on POSIX */
    }

    static inline void platform_cleanup(void) {
        /* No cleanup needed on POSIX */
    }

    static inline int socket_set_nonblocking(socket_t sock) {
        int flags = fcntl(sock, F_GETFL, 0);
        if (flags == -1) return -1;
        return fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    }

    static inline int socket_set_blocking(socket_t sock) {
        int flags = fcntl(sock, F_GETFL, 0);
        if (flags == -1) return -1;
        return fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
    }

    /* Thread functions */
    typedef void* (*thread_func_t)(void*);

    static inline int thread_create(thread_t* thread, thread_func_t func, void* arg) {
        return pthread_create(thread, NULL, func, arg);
    }

    static inline int thread_join(thread_t thread) {
        return pthread_join(thread, NULL);
    }

    static inline int thread_detach(thread_t thread) {
        return pthread_detach(thread);
    }

    /* Mutex functions */
    static inline int mutex_init(mutex_t* mutex) {
        return pthread_mutex_init(mutex, NULL);
    }

    static inline int mutex_lock(mutex_t* mutex) {
        return pthread_mutex_lock(mutex);
    }

    static inline int mutex_trylock(mutex_t* mutex) {
        return pthread_mutex_trylock(mutex);
    }

    static inline int mutex_unlock(mutex_t* mutex) {
        return pthread_mutex_unlock(mutex);
    }

    static inline int mutex_destroy(mutex_t* mutex) {
        return pthread_mutex_destroy(mutex);
    }

    static inline void platform_sleep_ms(int ms) {
        usleep(ms * 1000);
    }
#endif

/* Common socket helper functions */
static inline int socket_set_reuseaddr(socket_t sock) {
    int opt = 1;
    return setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
}

static inline int socket_set_nodelay(socket_t sock) {
    int opt = 1;
    return setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char*)&opt, sizeof(opt));
}

static inline int socket_set_keepalive(socket_t sock) {
    int opt = 1;
    return setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (const char*)&opt, sizeof(opt));
}

/* Send flags for cross-platform compatibility */
#ifndef _WIN32
    /* MSG_NOSIGNAL prevents SIGPIPE on broken pipe */
    #ifndef MSG_NOSIGNAL
        #define MSG_NOSIGNAL 0
    #endif
#else
    #define MSG_NOSIGNAL 0
#endif

#endif /* PLATFORM_H */
