/*
 * io.c
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

#include "io.h"

#include <string.h>
#include <libc_bridge.h>
#include <sys/stat.h>
#include <sys/unistd.h>
#include <malloc.h>
#include <stdbool.h>
#include <stdlib.h>
#include <psp2/io/dirent.h>

#include "utils/utils.h"
#include "utils/dialog.h"
#include "utils/loading_screen.h"
#include "main.h"
#include "so_util.h"

#include "_preload_files.c"
const int preload_files_len = sizeof(preload_files)/sizeof(preload_files[0]);

inmemfile** inmemfiles;
void* full_cache;

void preload() {
    inmemfiles = malloc(sizeof(inmemfile) * preload_files_len);

    if (inmemfiles == NULL)
        fatal_error("Cannot allocate memory to preload assets");

    char cache_path[256];
    char cache_info_path[256];
    snprintf(cache_path, 256, "%s/asset_cache.dat", DATA_PATH);
    snprintf(cache_info_path, 256, "%s/asset_cache_info.dat", DATA_PATH);
    if (file_exists(cache_path) && file_exists(cache_info_path)) {
        loading_screen_run(); // _quit() is called before SDL_CreateWindow()
        debugPrintf("Loading asset cache, time: %lli\n", current_timestamp());

        FILE* g = sceLibcBridge_fopen(cache_path, "rb");
        size_t full_cache_length;
        int ret = ffullread(g, &full_cache, &full_cache_length, 256 * 1024);
        debugPrintf("Read %i bytes, ret %i\n", full_cache_length, ret);
        sceLibcBridge_fclose(g);

        FILE* f = fopen(cache_info_path, "r");
        for (int i = 0; i < preload_files_len; ++i) {
            size_t offset;
            size_t fsize;

            fscanf(f, "%i %i\n", &offset, &fsize); // NOLINT(cert-err34-c)

            inmemfile* imf = malloc(sizeof(inmemfile));
            imf->buf = (void*)(full_cache+offset);
            imf->size = fsize;

            inmemfiles[i] = imf;
        }
        fclose(f);

        debugPrintf("Done loading, time: %lli\n", current_timestamp());
    } else {
        loading_screen_run_assets_preloader();
        debugPrintf("Started asset preload, time: %lli\n", current_timestamp());

        size_t total_size = 0;

        for (int i = 0; i < preload_files_len; ++i) {
            FILE* f = sceLibcBridge_fopen(preload_files[i], "rb");
            inmemfile* imf = malloc(sizeof(inmemfile));
            ffullread(f, &imf->buf, &imf->size, 512);
            inmemfiles[i] = imf;
            sceLibcBridge_fclose(f);
            total_size += imf->size;

            float progress = (float)(i+1) / (float)preload_files_len;
            loading_screen_update_assets_preloader(progress);
        }

        void * buf_to_save = malloc(total_size);
        FILE * f = sceLibcBridge_fopen(cache_info_path, "w");
        size_t offset = 0;
        int lines_offset = 0;
        for (int i = 0; i < preload_files_len; ++i) {
            char line[64];
            int x = snprintf(line, 64, "%i %i\n", offset, inmemfiles[i]->size);
            sceLibcBridge_fwrite(line, x, 1, f);
            lines_offset += x;
            sceLibcBridge_fseek(f, lines_offset, SEEK_SET);

            memcpy(buf_to_save+offset, inmemfiles[i]->buf, inmemfiles[i]->size);
            offset += inmemfiles[i]->size;
        }
        sceLibcBridge_fclose(f);

        FILE * g = sceLibcBridge_fopen(cache_path, "w");
        sceLibcBridge_fwrite(buf_to_save, total_size, 1, g);
        sceLibcBridge_fclose(g);

        free(buf_to_save);

        debugPrintf("Done assets preload, time: %lli\n", current_timestamp());
        loading_screen_quit();
        loading_screen_run(); // _quit is called before SDL_CreateWindow()
    }
}

static int existing_files_capacity = 0;
static int existing_files_len = 0;
static char **existing_files = NULL;

static int compare_strings(const void *a, const void *b) {
    return strcmp(*(const char **)a, *(const char **)b);
}

static void add_existing_file(const char *path) {
    if (!existing_files) {
        existing_files_capacity = 1000;
        existing_files = malloc(sizeof(char *) * existing_files_capacity);
    }

    if (existing_files_len >= existing_files_capacity) {
        existing_files_capacity += existing_files_capacity / 10;
        existing_files = realloc(existing_files, sizeof(char *) * existing_files_capacity);
    }

    existing_files[existing_files_len] = strdup(path);
    existing_files_len++;
}

static void scan_directory_for_existing_files(const char *path) {
    SceUID dp = sceIoDopen(path);
    if (dp >= 0) {
        struct SceIoDirent ep;
        while (sceIoDread(dp, &ep) > 0) {
            char absolute_path[1024];
            snprintf(absolute_path, 1024, "%s/%s", path, ep.d_name);

            bool is_directory = (ep.d_stat.st_mode & SCE_S_IFDIR) != 0;

            if (is_directory) {
                scan_directory_for_existing_files(absolute_path);
            } else {
                add_existing_file(absolute_path);
            }
        }

        sceIoDclose(dp);
    }
}

void scan_existing_files() {
    scan_directory_for_existing_files(DATA_PATH);
    qsort(existing_files, existing_files_len, sizeof(char *), &compare_strings);
}

FILE *fopen_soloader(char *fname, char *mode) {
    char **preload_file = bsearch(&fname, preload_files, preload_files_len, sizeof(preload_files[0]), compare_strings);
    if (preload_file) {
        int preload_file_index = preload_file - preload_files;
        debugPrintf("fmemopen(%s)\n", fname);
        return fmemopen(inmemfiles[preload_file_index]->buf, inmemfiles[preload_file_index]->size, mode);
    }

    // This weird optimization had to be done because Baba Is You on every
    // level/world calls fopen() for an unimaginable amount of non-existing
    // files. The following code reduced level load from ~18 min to ~25 s.
    char **existing_file = bsearch(&fname, existing_files, existing_files_len, sizeof(existing_files[0]), compare_strings);
    if (existing_file) {
        debugPrintf("fopen(%s)\n", fname);
        return fopen(fname, mode);
    }

    // When writing to a new file, add it to the existing_files
    if (strchr(mode, 'w')) {
         debugPrintf("fopen(%s) - creating new file\n", fname);
         FILE *fp = fopen(fname, mode);

         if (fp) {
             add_existing_file(fname);
             qsort(existing_files, existing_files_len, sizeof(char *), &compare_strings);
         }

         return fp;
    }

    debugPrintf("skipping fopen(%s)\n", fname);
    return NULL;
}

int open_soloader(const char *fname, int flags) {
    debugPrintf("open(%s, %x)\n", fname, flags);
    return open(fname, flags);
}

int fstat_soloader(int fd, void *statbuf) {
    debugPrintf("Requested fstat for %i\n", fd);

    struct stat st;
    int res = fstat(fd, &st);
    if (res == 0)
        *(uint64_t *)(statbuf + 0x30) = st.st_size;
    return res;
}

int write_soloader(int fd, const void *buf, int count) {
    debugPrintf("Called write() for fd %i\n", fd);
    return write(fd, buf, count);
}

int close_soloader(int fd) {
    return close(fd);
}

int stat_soloader(const char *pathname, void *statbuf) {
    debugPrintf("Requested stat for %s\n", pathname);

    struct stat st;
    int res = stat(pathname, &st);
    if (res == 0)
        *(uint64_t *)(statbuf + 0x30) = st.st_size;
    return res;
}

void *AAssetManager_open(void *mgr, const char *filename, int mode) {
    debugPrintf("AAssetManager_open(%i, %s, %i)\n", (int)mgr, filename, mode);
    return 0;
}

void *AAssetManager_openDir(void *mgr, const char *dirName) {
    debugPrintf("AAssetManager_openDir(%p, %s)\n", mgr, dirName);
    return 0;
}

int fseeko_soloader(FILE * a, off_t b, int c) {
    debugPrintf("fseeko(%i)\n", (int32_t)a);
    return fseeko(a,b,c);
}

off_t ftello_soloader(FILE * a) {
    debugPrintf("ftello(%i)\n", (int32_t)a);
    return ftello(a);
}

int ffullread(FILE *f, void **dataptr, size_t *sizeptr, size_t chunk) {
    char *data = NULL, *temp;
    size_t size = 0;
    size_t used = 0;
    size_t n;

    if (f == NULL || dataptr == NULL || sizeptr == NULL)
        return FFULLREAD_INVALID;

    if (sceLibcBridge_ferror(f))
        return FFULLREAD_ERROR;

    while (1) {
        if (used + chunk + 1 > size) {
            size = used + chunk + 1;

            // Overflow check
            if (size <= used) {
                free(data);
                return FFULLREAD_TOOMUCH;
            }

            temp = realloc(data, size);
            if (temp == NULL) {
                free(data);
                return FFULLREAD_NOMEM;
            }
            data = temp;
        }

        n = sceLibcBridge_fread(data + used, 1, chunk, f);
        if (n == 0)
            break;

        used += n;
    }

    if (sceLibcBridge_ferror(f)) {
        free(data);
        return FFULLREAD_ERROR;
    }

    temp = realloc(data, used + 1);
    if (temp == NULL) {
        free(data);
        return FFULLREAD_NOMEM;
    }
    data = temp;
    data[used] = '\0';

    *dataptr = data;
    *sizeptr = used;

    return FFULLREAD_OK;
}

void platform_walk_folder(CppString *pathname, FolderCallback *callback) {
    void (*convert_path)(CppString *, CppString *) = (void *) so_symbol(&so_mod, "_Z12convert_pathRKNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE");
    void (*cpp_string_from_c)(CppString *, const char *) = (void *) so_symbol(&so_mod, "_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2IDnEEPKc");
    void (*cpp_string_free)(CppString *) = (void *) so_symbol(&so_mod, "_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED1Ev");

    CppString converted_path;
    convert_path(&converted_path, pathname);

    char *converted_path_c;
    if ((converted_path.raw[0] & 1) != 0) {
        converted_path_c = converted_path.external.data;
    } else {
        converted_path_c = (char *)&converted_path.raw[1];
    }

    char absolute_converted_path_c[1024];
    snprintf(absolute_converted_path_c, 1024, "%s/%s", DATA_PATH_INT, converted_path_c);

    debugPrintf("platform_walk_folder for %s\n", absolute_converted_path_c);

    SceUID dp = sceIoDopen(absolute_converted_path_c);
    if (dp >= 0) {
        struct SceIoDirent ep;
        while (sceIoDread(dp, &ep) > 0) {
            debugPrintf("platform_walk_folder found %s\n", ep.d_name);

            FilesystemItem fs_item;
            cpp_string_from_c(&fs_item.name, ep.d_name);
            fs_item.is_file = (ep.d_stat.st_mode & SCE_S_IFDIR) == 0;

            callback->vtable->onItem(callback, &fs_item);

            cpp_string_free(&fs_item.name);
        }

        sceIoDclose(dp);
    }

    cpp_string_free(&converted_path);
}
