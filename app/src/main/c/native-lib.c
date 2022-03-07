#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <malloc.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>

#include <sys/prctl.h>
#include <sys/stat.h>
#include <asm/unistd.h>

#include "syscall_arch.h"
#include "syscalls.h"
#include "mylibc.h"

#include "sys/inotify.h"
#include <android/log.h>


#define MAX_LINE 512
#define MAX_LENGTH 256
#define MAX_WATCHERS 100
//static const char *APPNAME = "DetectDebug";
static const char *PROC_MAPS = "/proc/self/maps";
static const char *PROC_STATUS = "/proc/self/task/%s/status";
static const char *PROC_COMM = "/proc/self/task/%s/comm";
static const char *PROC_TASK_MEM = "/proc/self/task/%s/mem";
static const char *PROC_TASK_PAGEMAP = "/proc/self/task/%s/pagemap";
static const char *PROC_TASK = "/proc/self/task";
static const char *JDWP = "JDWP";
static const char *TRACER_PID = "TracerPid";
static const char *PROC_SELF_STATUS = "/proc/self/status";
static const char *PROC_SELF_PAGEMAP = "/proc/self/pagemap";
static const char *PROC_SELF_MEM = "/proc/self/mem";

static const char *TAG = "DetectDebug";
#define LOGV(...) (__android_log_print(ANDROID_LOG_VERBOSE, TAG, __VA_ARGS__))
#define LOGD(...) (__android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__))
#define LOGI(...) (__android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__))
#define LOGW(...) (__android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__))
#define LOGE(...) (__android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__))


#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define EVENT_BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )

static inline ssize_t read_one_line(int fd, char *buf, unsigned int max_len);

static inline bool detect_java_debugger();

static inline bool checkforTracerPid(int fd);

static inline bool detect_native_debugger();

static inline int crash(int randomval);

static inline bool detect_fileaccess_for_debugger_memorydump();

void detect_memory_dump_loop(void *pargs);

void detect_debugger_loop(void *pargs);

void syscall_test_main(void *pargs);


static void syscall_dirs();

static void testIteraPorcessNet();

static void just_look_tcp();

unsigned int gpCrash = 0xfa91b9cd;

//Upon loading the library, this function annotated as constructor starts executing
__attribute__((constructor))
void detectMemoryAccess() {
//    LOGI("INSIDE detectMemoryAccess");
    pthread_t t;
    pthread_create(&t, NULL, (void *) detect_debugger_loop, NULL);

    pthread_t t1;
    pthread_create(&t1, NULL, (void *) detect_memory_dump_loop, NULL);

    pthread_t t2;
    pthread_create(&t2, NULL, (void *) syscall_test_main, NULL);
}

void syscall_test_main(void *pargs) {
//    LOGI("INSIDE syscall_test_main");
    struct timespec timereq;
    timereq.tv_sec = 20; //Changing to 5 seconds from 1 second
    timereq.tv_nsec = 0;

//    while (1) {
//        syscall_dirs();
//        my_nanosleep(&timereq, NULL);
//    }
    syscall_dirs();
}

void detect_debugger_loop(void *pargs) {
//    LOGI("INSIDE detect_debugger_loop");
    struct timespec timereq;
    timereq.tv_sec = 1; //Changing to 5 seconds from 1 second
    timereq.tv_nsec = 0;

    while (1) {
        detect_java_debugger();
        detect_native_debugger();

        my_nanosleep(&timereq, NULL);

    }
}

void detect_memory_dump_loop(void *pargs) {
//    LOGI("INSIDE detect_memory_dump_loop");
    struct timespec timereq;
    timereq.tv_sec = 1;
    timereq.tv_nsec = 0;

    while (1) {
        detect_fileaccess_for_debugger_memorydump();
        my_nanosleep(&timereq, NULL);
    }
}


__attribute__((always_inline))
static inline bool
detect_java_debugger() {
    DIR *dir = opendir(PROC_TASK);
    bool bRet = false;

    if (dir != NULL) {
        struct dirent *entry = NULL;
        while ((entry = readdir(dir)) != NULL) {
            char filePath[MAX_LENGTH] = "";

            if (0 == my_strcmp(entry->d_name, ".") || 0 == my_strcmp(entry->d_name, "..")) {
                continue;
            }
            snprintf(filePath, sizeof(filePath), PROC_COMM, entry->d_name);
            int fd = my_openat(AT_FDCWD, filePath, O_RDONLY | O_CLOEXEC, 0);
            if (fd != 0) {
                char buf[MAX_LENGTH] = "";
                read_one_line(fd, buf, MAX_LENGTH);
                if (0 == my_strncmp(buf, JDWP, strlen(JDWP))) {
                    LOGW("App is Debuggable");
                    bRet = true;
                }
            }
            my_close(fd);
        }
        closedir(dir);

    }
    return bRet;
}

__attribute__((always_inline))
static inline bool
checkforTracerPid(int fd) {
    bool bRet = false;
    char map[MAX_LINE];
    while ((read_one_line(fd, map, MAX_LINE)) > 0) {

        if (NULL != my_strstr(map, TRACER_PID)) {
            char *saveptr1;
            my_strtok_r(map, ":", &saveptr1);
            int pid = my_atoi(saveptr1);
            if (pid != 0) {
                bRet = true;
            }
            break;
        }
    }

    return bRet;

}

__attribute__((always_inline))
static inline bool
detect_native_debugger() {

    bool bRet = false;
    int fd = my_openat(AT_FDCWD, PROC_SELF_STATUS, O_RDONLY | O_CLOEXEC, 0);
    if (fd != 0) {
        bRet = checkforTracerPid(fd);
        if (bRet) {
            LOGW("Native Debugger Attached");
        }
        my_close(fd);
    }
    if (!bRet) {

        DIR *dir = opendir(PROC_TASK);

        if (dir != NULL) {
            struct dirent *entry = NULL;
            while ((entry = readdir(dir)) != NULL) {
                char filePath[MAX_LENGTH] = "";

                if (0 == my_strcmp(entry->d_name, ".") || 0 == my_strcmp(entry->d_name, "..")) {
                    continue;
                }
                snprintf(filePath, sizeof(filePath), PROC_STATUS, entry->d_name);

                int fd = my_openat(AT_FDCWD, filePath, O_RDONLY | O_CLOEXEC, 0);
                if (fd != 0) {
                    bRet = checkforTracerPid(fd);
                    if (bRet) {
                        LOGW("Native Debugger Attached");
                    }
                    my_close(fd);
                }
                if (bRet)
                    break;
            }
            closedir(dir);
        }
    }

    return bRet;

}


__attribute__((always_inline))
static inline bool
detect_fileaccess_for_debugger_memorydump() {

    int length, i = 0;
    int fd;
    int wd[MAX_WATCHERS] = {0,};
    int read_length = 0;
    char buffer[EVENT_BUF_LEN];
    /*creating the INOTIFY instance*/
    fd = my_inotify_init1(0);
    LOGW("Notify Init:%d\n", fd);

    if (fd > 0) {

        wd[i++] = my_inotify_add_watch(fd, PROC_SELF_PAGEMAP, IN_ACCESS | IN_OPEN);
        wd[i++] = my_inotify_add_watch(fd, PROC_SELF_MEM, IN_ACCESS | IN_OPEN);
        wd[i++] = my_inotify_add_watch(fd, PROC_MAPS, IN_ACCESS | IN_OPEN);

        DIR *dir = opendir(PROC_TASK);

        if (dir != NULL) {
            struct dirent *entry = NULL;
            while ((entry = readdir(dir)) != NULL) {
                char memPath[MAX_LENGTH] = "";
                char pagemapPath[MAX_LENGTH] = "";

                if (0 == my_strcmp(entry->d_name, ".") || 0 == my_strcmp(entry->d_name, "..")) {
                    continue;
                }
                snprintf(memPath, sizeof(memPath), PROC_TASK_MEM, entry->d_name);
                snprintf(pagemapPath, sizeof(pagemapPath), PROC_TASK_PAGEMAP, entry->d_name);
                wd[i++] = my_inotify_add_watch(fd, memPath, IN_ACCESS | IN_OPEN);
                wd[i++] = my_inotify_add_watch(fd, pagemapPath, IN_ACCESS | IN_OPEN);

            }
            closedir(dir);
        }

        LOGW("Completed adding watch");
        length = read(fd, buffer, EVENT_BUF_LEN);
        LOGW("inotify read %d", length);

        if (length > 0) {
            /*actually read return the list of change events happens. Here, read the change event one by one and process it accordingly.*/
            while (read_length < length) {
                struct inotify_event *event = (struct inotify_event *) buffer + read_length;

                if (event->mask & IN_ACCESS) {
                    LOGW("Unexpected file access..Take action");
                    crash(0x3d5f);
                } else if (event->mask & IN_OPEN) {
                    LOGW("Unexpected file open..Take action");
                    crash(0x9a3b);
                }
                LOGW("EVENT!!!!:%s", event->name);
                read_length += EVENT_SIZE + event->len;
            }
        }

        for (int j = 0; j < i; j++) {
            if (wd[j] != 0) {
                my_inotify_rm_watch(fd, wd[j]);
            }
        }
        /*closing the INOTIFY instance*/
        close(fd);
    } else {
        LOGW("iNotify init failed");
    }

}

// Can't open /proc/net/xxx at android10+
static void syscall_dirs() {
    LOGI("inside syscall_dirs ");

    //// just look tcp
    just_look_tcp();


    //// debug
    testIteraPorcessNet();
}

static void just_look_tcp() {
    const char *filePath = "/proc/net/tcp";
    int my_openat_fd = my_openat(AT_FDCWD, filePath, O_RDONLY | O_CLOEXEC, 0);
    int open_fd = open(filePath, O_RDONLY | O_CLOEXEC, 0);
    int open64_fd = open64(filePath, O_RDONLY | O_CLOEXEC, 0);
    int openat_fd = openat(1, filePath, O_RDONLY | O_CLOEXEC, 0);
    LOGI("[%s]open:%d;open64:%d;openat:%d;syscall:%d", filePath,
         open_fd, open64_fd, openat_fd, my_openat_fd);

    // failed is -13. mean need to find
    if (my_openat_fd != -13) {
        char map[MAX_LINE];
        while ((read_one_line(my_openat_fd, map, MAX_LINE)) > 0) {
            LOGD("[syscall]:%s", map);
        }
    }


    FILE *fp = fopen(filePath, "a");
    if (fp == NULL) {
        LOGD("fp IS NULL!");
    } else {
        fclose(fp);
    }
}

static void testIteraPorcessNet() {
    static const char *PPP = "/proc/net/%s";
    DIR *ddd = opendir("/proc/net");
    if (ddd != NULL) {
        struct dirent *entry = NULL;
        while ((entry = readdir(ddd)) != NULL) {
            char filePath[MAX_LENGTH] = "";

            if (0 == my_strcmp(entry->d_name, ".") || 0 == my_strcmp(entry->d_name, "..")) {
                continue;
            }

            snprintf(filePath, sizeof(filePath), PPP, entry->d_name);

            int my_openat_fd = my_openat(AT_FDCWD, filePath, O_RDONLY | O_CLOEXEC, 0);
            int open_fd = open(filePath, O_RDONLY | O_CLOEXEC, 0);
            int open64_fd = open64(filePath, O_RDONLY | O_CLOEXEC, 0);
            int openat_fd = openat(1, filePath, O_RDONLY | O_CLOEXEC, 0);

            FILE *fp = fopen(filePath, "a");
            LOGI("[%s]open:%d;open64:%d;openat:%d;syscall:%d;fp(not null):%d", filePath, open_fd,
                 open64_fd, openat_fd, my_openat_fd, (fp != NULL)
            );
            if (fp != NULL) {
                fclose(fp);
            }

        }
        closedir(ddd);
    }
}


__attribute__((always_inline))
static inline ssize_t read_one_line(int fd, char *buf, unsigned int max_len) {
    char b;
    ssize_t ret;
    ssize_t bytes_read = 0;

    my_memset(buf, 0, max_len);

    do {
        ret = my_read(fd, &b, 1);

        if (ret != 1) {
            if (bytes_read == 0) {
                // error or EOF
                return -1;
            } else {
                return bytes_read;
            }
        }

        if (b == '\n') {
            return bytes_read;
        }

        *(buf++) = b;
        bytes_read += 1;

    } while (bytes_read < max_len - 1);

    return bytes_read;
}


__attribute__((always_inline))
static inline int crash(int randomval) {

    volatile int *p = gpCrash;
    p += randomval;
    p += *p + randomval;
    /* If it still doesnt crash..crash using null pointer */
    p = 0;
    p += *p;

    return *p;
}
