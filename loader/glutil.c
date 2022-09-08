/*
 * glutil.c
 *
 * OpenGL API initializer, related functions.
 *
 * Copyright (C) 2021 Andy Nguyen
 * Copyright (C) 2021 Rinnegatamante
 * Copyright (C) 2022 Volodymyr Atamanenko
 *
 * This software may be modified and distributed under the terms
 * of the MIT license. See the LICENSE file for details.
 */

#include "glutil.h"
#include "utils/dialog.h"
#include "sha1.h"

#include <stdio.h>
#include <string.h>
#include <malloc.h>

void gl_init() {
#if GRAPHICS_API == GRAPHICS_API_PVR
    PVRSRV_PSP2_APPHINT hint;
    int ret;
    ret = sceKernelLoadStartModule("vs0:sys/external/libfios2.suprx", 0, NULL, 0, NULL, NULL);
    debugPrintf("libfios2.suprx ret %#010x\n", ret);

    ret = sceKernelLoadStartModule("vs0:sys/external/libc.suprx", 0, NULL, 0, NULL, NULL);
    debugPrintf("libc.suprx ret %#010x\n", ret);

    ret = sceKernelLoadStartModule("app0:/module/libgpu_es4_ext.suprx", 0, NULL, 0, NULL, NULL);
    debugPrintf("libgpu_es4_ext.suprx ret %#010x\n", ret);

    ret = sceKernelLoadStartModule("app0:/module/libIMGEGL.suprx", 0, NULL, 0, NULL, NULL);
    debugPrintf("libIMGEGL.suprx ret %#010x\n", ret);

    PVRSRVInitializeAppHint(&hint);
    hint.bDisableAsyncTextureOp = 1;
    PVRSRVCreateVirtualAppHint(&hint);
#else
    if (!file_exists("ur0:/data/libshacccg.suprx")
        && !file_exists("ur0:/data/external/libshacccg.suprx")) {
        fatal_error("Error libshacccg.suprx is not installed.");
    }
#endif
}

void glShaderSourceHook(GLuint shader, GLsizei count, const GLchar **string,
                        const GLint *length) {
    static const struct {
        const char *sha1;
        const char *compiled_shader_filename;
    } known_shaders[] = {
        { "005e0c26d62a3e269db61ebd4a311396699ecc6a", "simple.fs" }, // V423B
        { "f2f789c891280e43e583835dc69d9f190868907a", "simple.fs" }, // V471
        { "252204be98344df7ab6a69fe69b18d099a065daf", "glow.fs"   }, // V423B
        { "fd30057d9adba3816afe2159ed7168cbf299e814", "glow.fs"   }, // V471
        { "ac909e3068bedae0b2532e36bf60e951c29f9097", "simple.vs" }, // V423B
        { "edd8668a7ba200f129f6af6c8ea420573c928537", "simple.vs" }, // V471
        { "aebb80722a081f8771e28fa531b3886c1b71b826", "3d.fs"     }, // V423B
        { "00002d5acca1de06e46f0e12e773931380483412", "3d.fs"     }  // V471
    };

    uint32_t sha1[5];
    SHA1_CTX ctx;

    sha1_init(&ctx);
    sha1_update(&ctx, (uint8_t *)*string, *length);
    sha1_final(&ctx, (uint8_t *)sha1);

    char sha_name[64];
    snprintf(sha_name, sizeof(sha_name), "%08x%08x%08x%08x%08x",
             sha1[0], sha1[1], sha1[2], sha1[3], sha1[4]);

    const char *shader_name = sha_name;
    for (uint32_t i = 0; i < ARRAY_SIZE(known_shaders); i++) {
        if (strcmp(sha_name, known_shaders[i].sha1) == 0) {
            shader_name = known_shaders[i].compiled_shader_filename;
            break;
        }
    }

    char gxp_path[128];
    snprintf(gxp_path, sizeof(gxp_path), "%s/%s.gxp", GXP_PATH, shader_name);

    FILE *file = fopen(gxp_path, "rb");
    if (!file) {
        debugPrintf("[%i] Could not find %s\n", count, gxp_path);

        char glsl_path[128];
        snprintf(glsl_path, sizeof(glsl_path), "%s/%s.glsl",
                 GLSL_PATH, shader_name);

        file = fopen(glsl_path, "w");
        if (file) {
            fwrite(*string, 1, *length, file);
            fclose(file);
        }

        snprintf(gxp_path, sizeof(gxp_path), "%s/%s.gxp",
                 GXP_PATH, "simple.fs");
        file = fopen(gxp_path, "rb");
    }

    if (file) {
        size_t shaderSize;
        void *shaderBuf;

        fseek(file, 0, SEEK_END);
        shaderSize = ftell(file);
        fseek(file, 0, SEEK_SET);

        shaderBuf = malloc(shaderSize);
        fread(shaderBuf, 1, shaderSize, file);
        fclose(file);

        glShaderBinary(1, &shader, 0, shaderBuf, (int32_t)shaderSize);

        free(shaderBuf);
    }
}
