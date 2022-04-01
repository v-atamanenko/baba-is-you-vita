/* main.c -- World of Goo .so loader
 *
 * Copyright (C) 2021 Andy Nguyen
 * Copyright (C) 2022 Rinnegatamante
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#include <vitasdk.h>
#include <kubridge.h>
#include <vitashark.h>
#include <vitaGL.h>
#include <zlib.h>

#define AL_ALEXT_PROTOTYPES
#include <AL/alext.h>
#include <AL/efx.h>

#include <malloc.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <wchar.h>
#include <wctype.h>

#include <math.h>
#include <math_neon.h>

#include <errno.h>
#include <ctype.h>
#include <setjmp.h>
#include <sys/time.h>
#include <sys/stat.h>

#include "main.h"
#include "config.h"
#include "dialog.h"
#include "so_util.h"
#include "sha1.h"

uint32_t audio_player_play(char *path, uint8_t loop);
int audio_player_is_playing(int m);
void audio_player_stop(int m);
void audio_player_init();
void audio_player_stop_all_sounds();

typedef struct {
  unsigned char *elements;
  int size;
} jni_bytearray;

static char fake_vm[0x1000];
static char fake_env[0x1000];

int _newlib_heap_size_user = MEMORY_NEWLIB_MB * 1024 * 1024;

unsigned int _pthread_stack_default_user = 1 * 1024 * 1024;

so_module goo_mod;

void *__wrap_memcpy(void *dest, const void *src, size_t n) {
  return sceClibMemcpy(dest, src, n);
}

void *__wrap_memmove(void *dest, const void *src, size_t n) {
  return sceClibMemmove(dest, src, n);
}

void *__wrap_memset(void *s, int c, size_t n) {
  return sceClibMemset(s, c, n);
}

int debugPrintf(char *text, ...) {
#ifdef DEBUG
  //va_list list;
  //static char string[0x8000];

  //va_start(list, text);
  //vsprintf(string, text, list);
  //va_end(list);

  //SceUID fd = sceIoOpen("ux0:data/goo_log.txt", SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND, 0777);
  //if (fd >= 0) {
  //  sceIoWrite(fd, string, strlen(string));
  //  sceIoClose(fd);
  //}
#endif
  return 0;
}

int __android_log_print(int prio, const char *tag, const char *fmt, ...) {
#ifdef DEBUG
  //va_list list;
  //static char string[0x8000];

  //va_start(list, fmt);
  //vsprintf(string, fmt, list);
  //va_end(list);

  //printf("[LOG] %s: %s\n", tag, string);
#endif
  return 0;
}

int __android_log_vprint(int prio, const char *tag, const char *fmt, va_list list) {
#ifdef DEBUG
  //static char string[0x8000];

  //vsprintf(string, fmt, list);
  //va_end(list);

  //printf("[LOGV] %s: %s\n", tag, string);
#endif
  return 0;
}

int ret0(void) {
  return 0;
}

int ret1(void) {
  return 1;
}

int clock_gettime(int clk_ik, struct timespec *t) {
  struct timeval now;
  int rv = gettimeofday(&now, NULL);
  if (rv)
    return rv;
  t->tv_sec = now.tv_sec;
  t->tv_nsec = now.tv_usec * 1000;
  return 0;
}

int pthread_mutex_init_fake(pthread_mutex_t **uid,
                            const pthread_mutexattr_t *mutexattr) {
  pthread_mutex_t *m = calloc(1, sizeof(pthread_mutex_t));
  if (!m)
    return -1;

  const int recursive = (mutexattr && *(const int *)mutexattr == 1);
  *m = recursive ? PTHREAD_RECURSIVE_MUTEX_INITIALIZER
                 : PTHREAD_MUTEX_INITIALIZER;

  int ret = pthread_mutex_init(m, mutexattr);
  if (ret < 0) {
    free(m);
    return -1;
  }

  *uid = m;

  return 0;
}

int pthread_mutex_destroy_fake(pthread_mutex_t **uid) {
  if (uid && *uid && (uintptr_t)*uid > 0x8000) {
    pthread_mutex_destroy(*uid);
    free(*uid);
    *uid = NULL;
  }
  return 0;
}

int pthread_mutex_lock_fake(pthread_mutex_t **uid) {
  int ret = 0;
  if (!*uid) {
    ret = pthread_mutex_init_fake(uid, NULL);
  } else if ((uintptr_t)*uid == 0x4000) {
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    ret = pthread_mutex_init_fake(uid, &attr);
    pthread_mutexattr_destroy(&attr);
  } else if ((uintptr_t)*uid == 0x8000) {
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
    ret = pthread_mutex_init_fake(uid, &attr);
    pthread_mutexattr_destroy(&attr);
  }
  if (ret < 0)
    return ret;
  return pthread_mutex_lock(*uid);
}

int pthread_mutex_unlock_fake(pthread_mutex_t **uid) {
  int ret = 0;
  if (!*uid) {
    ret = pthread_mutex_init_fake(uid, NULL);
  } else if ((uintptr_t)*uid == 0x4000) {
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    ret = pthread_mutex_init_fake(uid, &attr);
    pthread_mutexattr_destroy(&attr);
  } else if ((uintptr_t)*uid == 0x8000) {
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
    ret = pthread_mutex_init_fake(uid, &attr);
    pthread_mutexattr_destroy(&attr);
  }
  if (ret < 0)
    return ret;
  return pthread_mutex_unlock(*uid);
}

int pthread_cond_init_fake(pthread_cond_t **cnd, const int *condattr) {
  pthread_cond_t *c = calloc(1, sizeof(pthread_cond_t));
  if (!c)
    return -1;

  *c = PTHREAD_COND_INITIALIZER;

  int ret = pthread_cond_init(c, NULL);
  if (ret < 0) {
    free(c);
    return -1;
  }

  *cnd = c;

  return 0;
}

int pthread_cond_broadcast_fake(pthread_cond_t **cnd) {
  if (!*cnd) {
    if (pthread_cond_init_fake(cnd, NULL) < 0)
      return -1;
  }
  return pthread_cond_broadcast(*cnd);
}

int pthread_cond_signal_fake(pthread_cond_t **cnd) {
  if (!*cnd) {
    if (pthread_cond_init_fake(cnd, NULL) < 0)
      return -1;
  }
  return pthread_cond_signal(*cnd);
}

int pthread_cond_destroy_fake(pthread_cond_t **cnd) {
  if (cnd && *cnd) {
    pthread_cond_destroy(*cnd);
    free(*cnd);
    *cnd = NULL;
  }
  return 0;
}

int pthread_cond_wait_fake(pthread_cond_t **cnd, pthread_mutex_t **mtx) {
  if (!*cnd) {
    if (pthread_cond_init_fake(cnd, NULL) < 0)
      return -1;
  }
  return pthread_cond_wait(*cnd, *mtx);
}

int pthread_cond_timedwait_fake(pthread_cond_t **cnd, pthread_mutex_t **mtx,
                                const struct timespec *t) {
  if (!*cnd) {
    if (pthread_cond_init_fake(cnd, NULL) < 0)
      return -1;
  }
  return pthread_cond_timedwait(*cnd, *mtx, t);
}

int pthread_create_fake(pthread_t *thread, const void *unused, void *entry,
                        void *arg) {
  return pthread_create(thread, NULL, entry, arg);
}

int pthread_once_fake(volatile int *once_control, void (*init_routine)(void)) {
  if (!once_control || !init_routine)
    return -1;
  if (__sync_lock_test_and_set(once_control, 1) == 0)
    (*init_routine)();
  return 0;
}

int GetCurrentThreadId(void) {
  return sceKernelGetThreadId();
}

extern void *__aeabi_ldiv0;

int GetEnv(void *vm, void **env, int r2) {
  *env = fake_env;
  return 0;
}

int DoesFileExistInApk(void *this, const char *file) {
  char real_path[128];
  sprintf(real_path, "ux0:data/goo/%s.mp3", file);
  return file_exists(real_path) ? 1 : 0;
}

void patch_game(void) {
  hook_addr(so_symbol(&goo_mod, "__aeabi_ldiv0"), (uintptr_t)&__aeabi_ldiv0);
  hook_addr(so_symbol(&goo_mod, "_ZN3Boy14AndroidStorage18DoesFileExistInApkEPKc"), (uintptr_t)&DoesFileExistInApk);
  hook_addr(so_symbol(&goo_mod, "_ZN3Boy18AndroidEnvironment8debugLogEPKcz"), (uintptr_t)&ret0);
}

extern void *__aeabi_atexit;
extern void *__aeabi_idiv;
extern void *__aeabi_idivmod;
extern void *__aeabi_ldivmod;
extern void *__aeabi_uidiv;
extern void *__aeabi_uidivmod;
extern void *__aeabi_uldivmod;
extern void *__cxa_atexit;
extern void *__cxa_finalize;
extern void *__gnu_unwind_frame;
extern void *__stack_chk_fail;
int open(const char *pathname, int flags);

static int __stack_chk_guard_fake = 0x42424242;

static char *__ctype_ = (char *)&_ctype_;

static FILE __sF_fake[0x100][3];

int stat_hook(const char *pathname, void *statbuf) {
  char real_fname[128];
  sprintf(real_fname, "%s.mp3", pathname);
  
  struct stat st;
  int res = stat(real_fname, &st);
  if (res == 0)
    *(uint64_t *)(statbuf + 0x30) = st.st_size;
  return res;
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd,
           off_t offset) {
  return malloc(length);
}

int munmap(void *addr, size_t length) {
  free(addr);
  return 0;
}

FILE *fopen_hook(char *fname, char *mode) {
  char real_fname[128];
  sprintf(real_fname, "%s.mp3", fname);

  return fopen(real_fname, mode);
}

int is_pers2 = 0;
char *save_buf;
int save_ptr = 0;

int open_hook(const char *fname, int flags) {
  is_pers2 = strstr(fname, "pers2.dat") ? 1 : 0;
  if (is_pers2) {
	save_buf = (char *)malloc(0x40000);
  }
  char real_fname[128];
  sprintf(real_fname, "%s.mp3", fname);

  return open(real_fname, flags);
}

int fstat_hook(int fd, void *statbuf) {
  struct stat st;
  int res = fstat(fd, &st);
  if (res == 0)
    *(uint64_t *)(statbuf + 0x30) = st.st_size;
  return res;
}

int write_hook(int fd, const void *buf, int count) {
  if (is_pers2) {
    if (count == 1) {
      save_buf[save_ptr] = *(char *)buf;
    } else {
      sceClibMemcpy(&save_buf[save_ptr], buf, count);
	}
	save_ptr += count;
	return count;
  } else {
    return write(fd, buf, count);
  }
}

int close_hook(int fd) {
  if (is_pers2) {
    write(fd, save_buf, save_ptr);
    free(save_buf);
    is_pers2 = 0;
	save_ptr = 0;
  }
  return close(fd);
}

static so_default_dynlib default_dynlib[] = {
  { "__aeabi_atexit", (uintptr_t)&__aeabi_atexit },
  { "__android_log_print", (uintptr_t)&__android_log_print },
  { "__android_log_vprint", (uintptr_t)&__android_log_vprint },
  { "__cxa_atexit", (uintptr_t)&__cxa_atexit },
  { "__cxa_finalize", (uintptr_t)&__cxa_finalize },
  { "__errno", (uintptr_t)&__errno },
  { "__gnu_unwind_frame", (uintptr_t)&__gnu_unwind_frame },
  // { "__google_potentially_blocking_region_begin", (uintptr_t)&__google_potentially_blocking_region_begin },
  // { "__google_potentially_blocking_region_end", (uintptr_t)&__google_potentially_blocking_region_end },
  { "__sF", (uintptr_t)&__sF_fake },
  { "__stack_chk_fail", (uintptr_t)&__stack_chk_fail },
  { "__stack_chk_guard", (uintptr_t)&__stack_chk_guard_fake },
  { "_ctype_", (uintptr_t)&__ctype_ },
  { "abort", (uintptr_t)&abort },
  // { "accept", (uintptr_t)&accept },
  { "acos", (uintptr_t)&acos },
  { "acosf", (uintptr_t)&acosf },
  { "asin", (uintptr_t)&asin },
  { "asinf", (uintptr_t)&asinf },
  { "atan", (uintptr_t)&atan },
  { "atan2", (uintptr_t)&atan2 },
  { "atan2f", (uintptr_t)&atan2f },
  { "atanf", (uintptr_t)&atanf },
  { "atoi", (uintptr_t)&atoi },
  { "atoll", (uintptr_t)&atoll },
  // { "bind", (uintptr_t)&bind },
  { "bsearch", (uintptr_t)&bsearch },
  { "btowc", (uintptr_t)&btowc },
  { "calloc", (uintptr_t)&calloc },
  { "ceil", (uintptr_t)&ceil },
  { "ceilf", (uintptr_t)&ceilf },
  { "clearerr", (uintptr_t)&clearerr },
  { "clock_gettime", (uintptr_t)&clock_gettime },
  { "close", (uintptr_t)&close_hook },
  { "cos", (uintptr_t)&cos },
  { "cosf", (uintptr_t)&cosf },
  { "cosh", (uintptr_t)&cosh },
  { "crc32", (uintptr_t)&crc32 },
  { "dlopen", (uintptr_t)&ret0 },
  { "exit", (uintptr_t)&exit },
  { "exp", (uintptr_t)&exp },
  { "expf", (uintptr_t)&expf },
  { "fclose", (uintptr_t)&fclose },
  { "fcntl", (uintptr_t)&ret0 },
  { "fdopen", (uintptr_t)&fdopen },
  { "ferror", (uintptr_t)&ferror },
  { "fflush", (uintptr_t)&fflush },
  { "fgets", (uintptr_t)&fgets },
  { "floor", (uintptr_t)&floor },
  { "floorf", (uintptr_t)&floorf },
  { "fmod", (uintptr_t)&fmod },
  { "fmodf", (uintptr_t)&fmodf },
  { "fopen", (uintptr_t)&fopen_hook },
  { "fprintf", (uintptr_t)&fprintf },
  { "fputc", (uintptr_t)&fputc },
  { "fputs", (uintptr_t)&fputs },
  { "fread", (uintptr_t)&fread },
  { "free", (uintptr_t)&free },
  { "frexp", (uintptr_t)&frexp },
  { "frexpf", (uintptr_t)&frexpf },
  { "fseek", (uintptr_t)&fseek },
  { "fstat", (uintptr_t)&fstat_hook },
  { "ftell", (uintptr_t)&ftell },
  { "fwrite", (uintptr_t)&fwrite },
  { "getc", (uintptr_t)&getc },
  { "getenv", (uintptr_t)&ret0 },
  { "getwc", (uintptr_t)&getwc },
  { "gettimeofday", (uintptr_t)&gettimeofday },
  { "glAlphaFunc", (uintptr_t)&glAlphaFunc },
  { "glBindBuffer", (uintptr_t)&glBindBuffer },
  { "glBindTexture", (uintptr_t)&glBindTexture },
  { "glBlendFunc", (uintptr_t)&glBlendFunc },
  { "glBufferData", (uintptr_t)&glBufferData },
  { "glClear", (uintptr_t)&glClear },
  { "glClearColor", (uintptr_t)&glClearColor },
  { "glClearDepthf", (uintptr_t)&glClearDepthf },
  { "glColorPointer", (uintptr_t)&glColorPointer },
  { "glCompressedTexImage2D", (uintptr_t)&glCompressedTexImage2D },
  { "glDeleteBuffers", (uintptr_t)&glDeleteBuffers },
  { "glDeleteTextures", (uintptr_t)&glDeleteTextures },
  { "glDepthFunc", (uintptr_t)&glDepthFunc },
  { "glDepthMask", (uintptr_t)&glDepthMask },
  { "glDisable", (uintptr_t)&glDisable },
  { "glDrawElements", (uintptr_t)&glDrawElements },
  { "glEnable", (uintptr_t)&glEnable },
  { "glEnableClientState", (uintptr_t)&glEnableClientState },
  { "glGenBuffers", (uintptr_t)&glGenBuffers },
  { "glGenTextures", (uintptr_t)&glGenTextures },
  { "glGetError", (uintptr_t)&glGetError },
  { "glLoadIdentity", (uintptr_t)&glLoadIdentity },
  { "glMatrixMode", (uintptr_t)&glMatrixMode },
  { "glMultMatrixx", (uintptr_t)&glMultMatrixx },
  { "glOrthof", (uintptr_t)&glOrthof },
  { "glPixelStorei", (uintptr_t)&ret0 },
  { "glPopMatrix", (uintptr_t)&glPopMatrix },
  { "glPushMatrix", (uintptr_t)&glPushMatrix },
  { "glTexCoordPointer", (uintptr_t)&glTexCoordPointer },
  { "glTexImage2D", (uintptr_t)&glTexImage2D },
  { "glTexParameteri", (uintptr_t)&glTexParameteri },
  { "glTexSubImage2D", (uintptr_t)&glTexSubImage2D },
  { "glTranslatex", (uintptr_t)&glTranslatex },
  { "glVertexPointer", (uintptr_t)&glVertexPointer },
  { "glViewport", (uintptr_t)&glViewport },
  { "gzopen", (uintptr_t)&ret0 },
  { "inflate", (uintptr_t)&inflate },
  { "inflateEnd", (uintptr_t)&inflateEnd },
  { "inflateInit_", (uintptr_t)&inflateInit_ },
  { "inflateReset", (uintptr_t)&inflateReset },
  { "isalnum", (uintptr_t)&isalnum },
  { "isalpha", (uintptr_t)&isalpha },
  { "iscntrl", (uintptr_t)&iscntrl },
  { "islower", (uintptr_t)&islower },
  { "ispunct", (uintptr_t)&ispunct },
  { "isprint", (uintptr_t)&isprint },
  { "isspace", (uintptr_t)&isspace },
  { "isupper", (uintptr_t)&isupper },
  { "iswalpha", (uintptr_t)&iswalpha },
  { "iswcntrl", (uintptr_t)&iswcntrl },
  { "iswctype", (uintptr_t)&iswctype },
  { "iswdigit", (uintptr_t)&iswdigit },
  { "iswdigit", (uintptr_t)&iswdigit },
  { "iswlower", (uintptr_t)&iswlower },
  { "iswprint", (uintptr_t)&iswprint },
  { "iswpunct", (uintptr_t)&iswpunct },
  { "iswspace", (uintptr_t)&iswspace },
  { "iswupper", (uintptr_t)&iswupper },
  { "iswxdigit", (uintptr_t)&iswxdigit },
  { "isxdigit", (uintptr_t)&isxdigit },
  { "ldexp", (uintptr_t)&ldexp },
  // { "listen", (uintptr_t)&listen },
  { "localtime_r", (uintptr_t)&localtime_r },
  { "log", (uintptr_t)&log },
  { "log10", (uintptr_t)&log10 },
  { "longjmp", (uintptr_t)&longjmp },
  { "lrand48", (uintptr_t)&lrand48 },
  { "lrint", (uintptr_t)&lrint },
  { "lrintf", (uintptr_t)&lrintf },
  { "lseek", (uintptr_t)&lseek },
  { "malloc", (uintptr_t)&malloc },
  { "mbrtowc", (uintptr_t)&mbrtowc },
  { "memchr", (uintptr_t)&sceClibMemchr },
  { "memcmp", (uintptr_t)&memcmp },
  { "memcpy", (uintptr_t)&sceClibMemcpy },
  { "memmove", (uintptr_t)&sceClibMemmove },
  { "memset", (uintptr_t)&sceClibMemset },
  { "mkdir", (uintptr_t)&mkdir },
  { "mmap", (uintptr_t)&mmap},
  { "munmap", (uintptr_t)&munmap},
  { "modf", (uintptr_t)&modf },
  // { "poll", (uintptr_t)&poll },
  { "open", (uintptr_t)&open_hook },
  { "pow", (uintptr_t)&pow },
  { "powf", (uintptr_t)&powf },
  { "printf", (uintptr_t)&printf },
  { "pthread_attr_destroy", (uintptr_t)&ret0 },
  { "pthread_attr_init", (uintptr_t)&ret0 },
  { "pthread_attr_setdetachstate", (uintptr_t)&ret0 },
  { "pthread_cond_broadcast", (uintptr_t)&pthread_cond_broadcast_fake},
  { "pthread_cond_wait", (uintptr_t)&pthread_cond_wait_fake},
  { "pthread_create", (uintptr_t)&pthread_create_fake },
  { "pthread_getschedparam", (uintptr_t)&pthread_getschedparam },
  { "pthread_getspecific", (uintptr_t)&pthread_getspecific },
  { "pthread_key_create", (uintptr_t)&pthread_key_create },
  { "pthread_key_delete", (uintptr_t)&pthread_key_delete },
  { "pthread_mutex_destroy", (uintptr_t)&pthread_mutex_destroy_fake },
  { "pthread_mutex_init", (uintptr_t)&pthread_mutex_init_fake },
  { "pthread_mutex_lock", (uintptr_t)&pthread_mutex_lock_fake },
  { "pthread_mutex_unlock", (uintptr_t)&pthread_mutex_unlock_fake },
  { "pthread_once", (uintptr_t)&pthread_once_fake },
  { "pthread_self", (uintptr_t)&pthread_self },
  { "pthread_setschedparam", (uintptr_t)&pthread_setschedparam },
  { "pthread_setspecific", (uintptr_t)&pthread_setspecific },
  { "putc", (uintptr_t)&putc },
  { "putwc", (uintptr_t)&putwc },
  { "qsort", (uintptr_t)&qsort },
  { "read", (uintptr_t)&read },
  { "realloc", (uintptr_t)&realloc },
  // { "recv", (uintptr_t)&recv },
  { "rint", (uintptr_t)&rint },
  // { "send", (uintptr_t)&send },
  // { "sendto", (uintptr_t)&sendto },
  { "setenv", (uintptr_t)&ret0 },
  { "setjmp", (uintptr_t)&setjmp },
  // { "setlocale", (uintptr_t)&setlocale },
  // { "setsockopt", (uintptr_t)&setsockopt },
  { "setvbuf", (uintptr_t)&setvbuf },
  { "sin", (uintptr_t)&sin },
  { "sinf", (uintptr_t)&sinf },
  { "sinh", (uintptr_t)&sinh },
  { "snprintf", (uintptr_t)&snprintf },
  // { "socket", (uintptr_t)&socket },
  { "sprintf", (uintptr_t)&sprintf },
  { "sqrt", (uintptr_t)&sqrt },
  { "sqrtf", (uintptr_t)&sqrtf },
  { "srand48", (uintptr_t)&srand48 },
  { "sscanf", (uintptr_t)&sscanf },
  { "stat", (uintptr_t)&stat_hook },
  { "strcasecmp", (uintptr_t)&strcasecmp },
  { "strcat", (uintptr_t)&strcat },
  { "strchr", (uintptr_t)&strchr },
  { "strcmp", (uintptr_t)&sceClibStrcmp },
  { "strcoll", (uintptr_t)&strcoll },
  { "strcpy", (uintptr_t)&strcpy },
  { "strcspn", (uintptr_t)&strcspn },
  { "strerror", (uintptr_t)&strerror },
  { "strftime", (uintptr_t)&strftime },
  { "strlen", (uintptr_t)&strlen },
  { "strncasecmp", (uintptr_t)&sceClibStrncasecmp },
  { "strncat", (uintptr_t)&sceClibStrncat },
  { "strncmp", (uintptr_t)&sceClibStrncmp },
  { "strncpy", (uintptr_t)&sceClibStrncpy },
  { "strpbrk", (uintptr_t)&strpbrk },
  { "strrchr", (uintptr_t)&sceClibStrrchr },
  { "strstr", (uintptr_t)&sceClibStrstr },
  { "strtod", (uintptr_t)&strtod },
  { "strtol", (uintptr_t)&strtol },
  { "strtoul", (uintptr_t)&strtoul },
  { "strxfrm", (uintptr_t)&strxfrm },
  { "sysconf", (uintptr_t)&ret0 },
  { "tan", (uintptr_t)&tan },
  { "tanf", (uintptr_t)&tanf },
  { "tanh", (uintptr_t)&tanh },
  { "time", (uintptr_t)&time },
  { "tolower", (uintptr_t)&tolower },
  { "toupper", (uintptr_t)&toupper },
  { "towlower", (uintptr_t)&towlower },
  { "towupper", (uintptr_t)&towupper },
  { "ungetc", (uintptr_t)&ungetc },
  { "ungetwc", (uintptr_t)&ungetwc },
  { "usleep", (uintptr_t)&usleep },
  { "vfprintf", (uintptr_t)&vfprintf },
  { "vprintf", (uintptr_t)&vprintf },
  { "vsnprintf", (uintptr_t)&vsnprintf },
  { "vsprintf", (uintptr_t)&vsprintf },
  { "vswprintf", (uintptr_t)&vswprintf },
  { "wcrtomb", (uintptr_t)&wcrtomb },
  { "wcscoll", (uintptr_t)&wcscoll },
  { "wcscmp", (uintptr_t)&wcscmp },
  { "wcsncpy", (uintptr_t)&wcsncpy },
  { "wcsftime", (uintptr_t)&wcsftime },
  { "wcslen", (uintptr_t)&wcslen },
  { "wcsxfrm", (uintptr_t)&wcsxfrm },
  { "wctob", (uintptr_t)&wctob },
  { "wctype", (uintptr_t)&wctype },
  { "wmemchr", (uintptr_t)&wmemchr },
  { "wmemcmp", (uintptr_t)&wmemcmp },
  { "wmemcpy", (uintptr_t)&wmemcpy },
  { "wmemmove", (uintptr_t)&wmemmove },
  { "wmemset", (uintptr_t)&wmemset },
  { "write", (uintptr_t)&write_hook },
  // { "writev", (uintptr_t)&writev },
};

int check_kubridge(void) {
  int search_unk[2];
  return _vshKernelSearchModuleByName("kubridge", search_unk);
}

int file_exists(const char *path) {
  SceIoStat stat;
  return sceIoGetstat(path, &stat) >= 0;
}

enum MethodIDs {
  UNKNOWN = 0,
  INIT,
  GET_APK_PATH,
  GET_EXTERNAL_STORAGE_PATH,
  GET_INTERNAL_STORAGE_PATH,
  PLAY_SOUND,
  LOAD_SOUND,
  STOP_SOUND,
  STOP_ALL_SOUNDS,
  UNLOAD_SOUND,
  IS_PLAYING,
  IS_VBO_SUPPORTED,
  GET_LANGUAGE
} MethodIDs;

typedef struct {
  char *name;
  enum MethodIDs id;
} NameToMethodID;

static NameToMethodID name_to_method_ids[] = {
  { "<init>", INIT },
  { "getApkPath", GET_APK_PATH },
  { "getExternalStoragePath", GET_EXTERNAL_STORAGE_PATH },
  { "getInternalStoragePath", GET_INTERNAL_STORAGE_PATH },
  { "playSound", PLAY_SOUND },
  { "loadSound", LOAD_SOUND },
  { "stopSound", STOP_SOUND },
  { "stopAllSounds", STOP_ALL_SOUNDS },
  { "unloadSound", UNLOAD_SOUND },
  { "isPlaying", IS_PLAYING },
  { "isVBOSupported", IS_VBO_SUPPORTED },
  { "getLanguage", GET_LANGUAGE },
};

int GetMethodID(void *env, void *class, const char *name, const char *sig) {
  printf("%s\n", name);

  for (int i = 0; i < sizeof(name_to_method_ids) / sizeof(NameToMethodID); i++) {
    if (strcmp(name, name_to_method_ids[i].name) == 0) {
      return name_to_method_ids[i].id;
    }
  }

  return UNKNOWN;
}

int GetStaticMethodID(void *env, void *class, const char *name, const char *sig) {
  for (int i = 0; i < sizeof(name_to_method_ids) / sizeof(NameToMethodID); i++) {
    if (strcmp(name, name_to_method_ids[i].name) == 0)
      return name_to_method_ids[i].id;
  }

  return UNKNOWN;
}

void CallStaticVoidMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
}

int CallStaticBooleanMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
  return 0;
}

uint64_t CallLongMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
  return -1;
}

void *FindClass(void) {
  return (void *)0x41414141;
}

void *NewGlobalRef(void *env, char *str) {
  if (!str)
    return (void *)0x42424242;
  
  
  if (str[0] != 'r') {
    return str;
  } else {
    void *r = malloc(strlen(str) + 14);
    sprintf(r, "ux0:data/goo/%s", str);
    return r;
  }
}

void DeleteGlobalRef(void *env, char *str) {
  if (str && str[0] == 'u')
    free(str);
}

void *NewObjectV(void *env, void *clazz, int methodID, uintptr_t args) {
  return (void *)0x43434343;
}

void *GetObjectClass(void *env, void *obj) {
  return (void *)0x44444444;
}

char *NewStringUTF(void *env, char *bytes) {
  return bytes;
}

char *GetStringUTFChars(void *env, char *string, int *isCopy) {
  return string;
}

int GetJavaVM(void *env, void **vm) {
  *vm = fake_vm;
  return 0;
}

int GetFieldID(void *env, void *clazz, const char *name, const char *sig) {
  return 0;
}

int GetBooleanField(void *env, void *obj, int fieldID) {
  return 0;
}

void *CallObjectMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
  int lang = -1;

  switch (methodID) {
  case GET_APK_PATH:
  case GET_EXTERNAL_STORAGE_PATH:
  case GET_INTERNAL_STORAGE_PATH:
    return DATA_PATH;
  case PLAY_SOUND:
    return audio_player_play(args[0], args[1]);
  case GET_LANGUAGE:
    sceAppUtilSystemParamGetInt(SCE_SYSTEM_PARAM_ID_LANG, &lang);
    switch (lang) {
    case SCE_SYSTEM_PARAM_LANG_ITALIAN:
      return "it";
    case SCE_SYSTEM_PARAM_LANG_GERMAN:
      return "de";
    case SCE_SYSTEM_PARAM_LANG_KOREAN:
      return "ko";
    case SCE_SYSTEM_PARAM_LANG_CHINESE_S:
    case SCE_SYSTEM_PARAM_LANG_CHINESE_T:
      return "ch";
    case SCE_SYSTEM_PARAM_LANG_SPANISH:
      return "es";
    case SCE_SYSTEM_PARAM_LANG_FRENCH:
      return "fr";
    case SCE_SYSTEM_PARAM_LANG_POLISH:
      return "pl";
    case SCE_SYSTEM_PARAM_LANG_DUTCH:
      return "nl";
    default:
      return NULL;
    }
  default:
    return NULL;
  }
}

int CallBooleanMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
  switch (methodID) {
  case IS_PLAYING:
    return (args[0] > 1) ? audio_player_is_playing(args[0]) : 0;
  case IS_VBO_SUPPORTED:
    return 1;
  default:
    return 0;
  }
}

void CallVoidMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
  switch (methodID) {
  case STOP_SOUND:
    audio_player_stop(args[0]);
    break;
  case STOP_ALL_SOUNDS:
    audio_player_stop_all_sounds();
    break;
  default:
    break;
  }
}

int GetIntField(void *env, void *obj, int fieldID) { return 0; }

enum {
  TOUCH_START = 0,
  ALL_TOUCH_END = 1,
  TOUCH_MOVE = 2,
  TOUCH_END = 6
};

int main(int argc, char *argv[]) {
  SceAppUtilInitParam init_param;
  SceAppUtilBootParam boot_param;
  memset(&init_param, 0, sizeof(SceAppUtilInitParam));
  memset(&boot_param, 0, sizeof(SceAppUtilBootParam));
  sceAppUtilInit(&init_param, &boot_param);
  
  sceTouchSetSamplingState(SCE_TOUCH_PORT_FRONT, SCE_TOUCH_SAMPLING_STATE_START);

  scePowerSetArmClockFrequency(444);
  scePowerSetBusClockFrequency(222);
  scePowerSetGpuClockFrequency(222);
  scePowerSetGpuXbarClockFrequency(166);

  if (check_kubridge() < 0)
    fatal_error("Error kubridge.skprx is not installed.");

  if (!file_exists("ur0:/data/libshacccg.suprx") && !file_exists("ur0:/data/external/libshacccg.suprx"))
    fatal_error("Error libshacccg.suprx is not installed.");

  if (so_load(&goo_mod, SO_PATH, LOAD_ADDRESS) < 0)
    fatal_error("Error could not load %s.", SO_PATH);

  so_relocate(&goo_mod);
  so_resolve(&goo_mod, default_dynlib, sizeof(default_dynlib), 0);

  patch_game();
  so_flush_caches(&goo_mod);

  so_initialize(&goo_mod);
  
  audio_player_init();
  
  vglSetupGarbageCollector(127, 0x20000);
  vglInitExtended(0, SCREEN_W, SCREEN_H, MEMORY_VITAGL_THRESHOLD_MB * 1024 * 1024, SCE_GXM_MULTISAMPLE_4X);

  memset(fake_vm, 'A', sizeof(fake_vm));
  *(uintptr_t *)(fake_vm + 0x00) = (uintptr_t)fake_vm; // just point to itself...
  *(uintptr_t *)(fake_vm + 0x10) = (uintptr_t)ret0;
  *(uintptr_t *)(fake_vm + 0x14) = (uintptr_t)ret0;
  *(uintptr_t *)(fake_vm + 0x18) = (uintptr_t)GetEnv;

  memset(fake_env, 'A', sizeof(fake_env));
  *(uintptr_t *)(fake_env + 0x00) = (uintptr_t)fake_env; // just point to itself...
  *(uintptr_t *)(fake_env + 0x18) = (uintptr_t)FindClass;
  *(uintptr_t *)(fake_env + 0x54) = (uintptr_t)NewGlobalRef;
  *(uintptr_t *)(fake_env + 0x58) = (uintptr_t)DeleteGlobalRef;
  *(uintptr_t *)(fake_env + 0x5C) = (uintptr_t)ret0; // DeleteLocalRef
  *(uintptr_t *)(fake_env + 0x74) = (uintptr_t)NewObjectV;
  *(uintptr_t *)(fake_env + 0x7C) = (uintptr_t)GetObjectClass;
  *(uintptr_t *)(fake_env + 0x84) = (uintptr_t)GetMethodID;
  *(uintptr_t *)(fake_env + 0x8C) = (uintptr_t)CallObjectMethodV;
  *(uintptr_t *)(fake_env + 0x98) = (uintptr_t)CallBooleanMethodV;
  *(uintptr_t *)(fake_env + 0xD4) = (uintptr_t)CallLongMethodV;
  *(uintptr_t *)(fake_env + 0xF8) = (uintptr_t)CallVoidMethodV;
  *(uintptr_t *)(fake_env + 0x178) = (uintptr_t)GetFieldID;
  *(uintptr_t *)(fake_env + 0x17C) = (uintptr_t)GetBooleanField;
  *(uintptr_t *)(fake_env + 0x190) = (uintptr_t)GetIntField;
  *(uintptr_t *)(fake_env + 0x1C4) = (uintptr_t)GetStaticMethodID;
  *(uintptr_t *)(fake_env + 0x1D8) = (uintptr_t)CallStaticBooleanMethodV;
  *(uintptr_t *)(fake_env + 0x238) = (uintptr_t)CallStaticVoidMethodV;
  *(uintptr_t *)(fake_env + 0x29C) = (uintptr_t)NewStringUTF;
  *(uintptr_t *)(fake_env + 0x2A4) = (uintptr_t)GetStringUTFChars;
  *(uintptr_t *)(fake_env + 0x2A8) = (uintptr_t)ret0;
  *(uintptr_t *)(fake_env + 0x36C) = (uintptr_t)GetJavaVM;

  int (* Java_com_twodboy_worldofgoo_WorldOfGoo_nativeOnCreate)(void *env, int a2, int a3, uint8_t a4, uint8_t a5) = (void *)so_symbol(&goo_mod, "Java_com_twodboy_worldofgoo_WorldOfGoo_nativeOnCreate");
  int (* Java_com_twodboy_worldofgoo_DemoRenderer_nativeRender)(void *env, int back_pressed, int menu_pressed) = (void *)so_symbol(&goo_mod, "Java_com_twodboy_worldofgoo_DemoRenderer_nativeRender");
  int (* Java_com_twodboy_worldofgoo_DemoRenderer_nativeOnSurfaceCreated)(void *env) = (void *)so_symbol(&goo_mod, "Java_com_twodboy_worldofgoo_DemoRenderer_nativeOnSurfaceCreated");
  int (* Java_com_twodboy_worldofgoo_DemoRenderer_nativeResize)(void *env, int a2, int w, int h) = (void *)so_symbol(&goo_mod, "Java_com_twodboy_worldofgoo_DemoRenderer_nativeResize");
  int (* Java_com_twodboy_worldofgoo_DemoRenderer_nativeTouchEvent)(void *env, int a2, int type, float x, float y, int id) = (void *)so_symbol(&goo_mod, "Java_com_twodboy_worldofgoo_DemoRenderer_nativeTouchEvent");
  
  Java_com_twodboy_worldofgoo_WorldOfGoo_nativeOnCreate(fake_env, 0, 0, 0, 0);
  Java_com_twodboy_worldofgoo_DemoRenderer_nativeOnSurfaceCreated(fake_env);
  Java_com_twodboy_worldofgoo_DemoRenderer_nativeResize(fake_env, 0, SCREEN_W, SCREEN_H);
  
  int lastX[SCE_TOUCH_MAX_REPORT] = {-1, -1, -1, -1, -1, -1, -1, -1};
  int lastY[SCE_TOUCH_MAX_REPORT] = {-1, -1, -1, -1, -1, -1, -1, -1};

  for (;;) {
    SceTouchData touch;
    sceTouchPeek(SCE_TOUCH_PORT_FRONT, &touch, 1);
    for (int i = 0; i < SCE_TOUCH_MAX_REPORT; i++) {
      if (i < touch.reportNum) {
        int x = (int)((float)touch.report[i].x * (float)SCREEN_W / 1920.0f);
        int y = (int)((float)touch.report[i].y * (float)SCREEN_H / 1088.0f);

        if (lastX[i] == -1 || lastY[i] == -1)
          Java_com_twodboy_worldofgoo_DemoRenderer_nativeTouchEvent(fake_env, 0, TOUCH_START, x, y, i);
        else if (lastX[i] != x || lastY[i] != y)
          Java_com_twodboy_worldofgoo_DemoRenderer_nativeTouchEvent(fake_env, 0, TOUCH_MOVE, x, y, i);
        lastX[i] = x;
        lastY[i] = y;
      } else {
        if (lastX[i] != -1 || lastY[i] != -1) {
          Java_com_twodboy_worldofgoo_DemoRenderer_nativeTouchEvent(fake_env, 0, TOUCH_END, lastX[i], lastY[i], i);
          lastX[i] = -1;
          lastY[i] = -1;
        }
      }
    }
    
    static uint32_t oldpad;
    SceCtrlData pad;
    sceCtrlPeekBufferPositive(0, &pad, 1);
    Java_com_twodboy_worldofgoo_DemoRenderer_nativeRender(fake_env, 0, ((pad.buttons & SCE_CTRL_START) && !(oldpad & SCE_CTRL_START)) ? 1 : 0);
    vglSwapBuffers(GL_FALSE);
    oldpad = pad.buttons;
  }

  return 0;
}
