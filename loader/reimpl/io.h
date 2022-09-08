/*
 * io.h
 *
 * Wrappers and implementations for some of IO functions for optimization
 * and bridging to SceLibc.
 *
 * Copyright (C) 2021 Andy Nguyen
 * Copyright (C) 2022 Rinnegatamante
 * Copyright (C) 2022 Volodymyr Atamanenko
 *
 * This software may be modified and distributed under the terms
 * of the MIT license. See the LICENSE file for details.
 */

#ifndef SOLOADER_IO_H
#define SOLOADER_IO_H

#include <stdio.h>

// vitasdk lacks proper definition of open() although it has its implementation
int open(const char *pathname, int flags);

FILE *fopen_soloader(char *fname, char *mode);

int open_soloader(const char *fname, int flags);

int fstat_soloader(int fd, void *statbuf);

int write_soloader(int fd, const void *buf, int count);

int close_soloader(int fd);

int stat_soloader(const char *pathname, void *statbuf);

void *AAssetManager_open(void *mgr, const char *filename, int mode);
void *AAssetManager_openDir(void *mgr, const char *dirName);

int fseeko_soloader(FILE * a, off_t b, int c);

off_t ftello_soloader(FILE * a);

int remove_soloader(const char *path);

// Chowdren's platform_walk_folder is a stub on Android, provide a real implementation

typedef union CppString {
    uint8_t raw[12];
    struct {
        uint32_t capacity;
        uint32_t size;
        char *data;
    } external;
} CppString;

typedef struct FilesystemItem {
    CppString name;
    uint8_t is_file;
} FilesystemItem;

struct FolderCallback;

typedef struct FolderCallback_VTable {
    void (*onItem)(struct FolderCallback *_this, FilesystemItem *item);
} FolderCallback_VTable;

typedef struct FolderCallback {
    FolderCallback_VTable *vtable;
} FolderCallback;

void platform_walk_folder(CppString *pathname, FolderCallback *callback);

/*
 * Stuff related to in-memory assets preloading.
 */

typedef struct inmemfile {
    void * buf;
    size_t size;
} inmemfile;

void preload();

void scan_existing_files();

#define FFULLREAD_OK      (0)
#define FFULLREAD_INVALID (-1) // Invalid params
#define FFULLREAD_ERROR   (-2) // File stream error
#define FFULLREAD_TOOMUCH (-3) // Too much input
#define FFULLREAD_NOMEM   (-4)

int ffullread(FILE *f, void **dataptr, size_t *sizeptr, size_t chunk);

#endif // SOLOADER_IO_H
