/* SPDX-License-Identifier: GPL-3.0-or-later
 * Linux presentation/input adapter for the separately linked Xita reference.
 * All SDL operations belong to one thread; guest scanout is copied before return.
 */
#include <SDL2/SDL.h>
#include <psp2/display.h>
#include <psp2/ctrl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static pthread_once_t once = PTHREAD_ONCE_INIT;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static uint8_t *pixels;
static unsigned width, height, serial;
static uint32_t buttons;
static uint8_t axes[4] = {128,128,128,128};
extern int __real_sceDisplaySetFrameBuf(const SceDisplayFrameBuf *, SceDisplaySetBufSync);
extern int __real_sceCtrlPeekBufferPositive(int, SceCtrlData *, int);

static void fail(const char *operation) {
    fprintf(stderr,"[linux/display] %s: %s\n",operation,SDL_GetError());
    exit(1);
}
static void *display_thread(void *unused) {
    (void)unused;
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_EVENTS)) fail("SDL_Init");
    SDL_Window *window = SDL_CreateWindow("Halo 2 — Xita Linux reference",
        SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,960,544,SDL_WINDOW_RESIZABLE);
    if (!window) fail("window");
    SDL_Renderer *renderer = SDL_CreateRenderer(window,-1,SDL_RENDERER_ACCELERATED);
    if (!renderer) renderer = SDL_CreateRenderer(window,-1,SDL_RENDERER_SOFTWARE);
    if (!renderer) fail("renderer");
    SDL_Texture *texture = NULL;
    unsigned tw=0,th=0,last=0;
    uint32_t old_buttons=0;
    fprintf(stderr,"[linux/display] ready driver=%s; Enter=Start Z=A X=B C=X V=Y; WASD=left stick, IJKL=right stick, arrows=D-pad, Q/E=triggers, Backspace=Back\n",SDL_GetCurrentVideoDriver());
    for (;;) {
        SDL_Event event;
        while (SDL_PollEvent(&event)) {
            if (event.type == SDL_QUIT) { SDL_Quit(); exit(0); }
        }
        const uint8_t *keys=SDL_GetKeyboardState(NULL);
        uint32_t b=0;
#define KEY(k,v) if(keys[SDL_SCANCODE_##k]) b |= SCE_CTRL_##v
        if (SDL_GetKeyboardFocus() == window) {
            KEY(RETURN,START); KEY(BACKSPACE,SELECT); KEY(Z,CROSS); KEY(X,CIRCLE);
            KEY(C,SQUARE); KEY(V,TRIANGLE); KEY(Q,LTRIGGER); KEY(E,RTRIGGER);
            KEY(UP,UP); KEY(DOWN,DOWN); KEY(LEFT,LEFT); KEY(RIGHT,RIGHT);
        }
#undef KEY
        pthread_mutex_lock(&lock);
        buttons=b;
        if (b!=old_buttons) {
            fprintf(stderr,"[linux/input] buttons=%08x frame=%u\n",b,serial);
            old_buttons=b;
        }
        const int focus=SDL_GetKeyboardFocus()==window;
        axes[0]=focus ? (keys[SDL_SCANCODE_D] ? 255 : keys[SDL_SCANCODE_A] ? 0 : 128) : 128;
        axes[1]=focus ? (keys[SDL_SCANCODE_S] ? 255 : keys[SDL_SCANCODE_W] ? 0 : 128) : 128;
        axes[2]=focus ? (keys[SDL_SCANCODE_L] ? 255 : keys[SDL_SCANCODE_J] ? 0 : 128) : 128;
        axes[3]=focus ? (keys[SDL_SCANCODE_K] ? 255 : keys[SDL_SCANCODE_I] ? 0 : 128) : 128;
        if (pixels && serial!=last) {
            if (tw!=width || th!=height) {
                SDL_DestroyTexture(texture);
                texture=SDL_CreateTexture(renderer,SDL_PIXELFORMAT_RGBA32,SDL_TEXTUREACCESS_STREAMING,width,height);
                if (!texture) fail("texture");
                tw=width; th=height;
                SDL_RenderSetLogicalSize(renderer,tw,th);
            }
            if (SDL_UpdateTexture(texture,NULL,pixels,width*4)) fail("texture upload");
            last=serial;
            if (last % 120 == 0) fprintf(stderr,"[linux/display] uploaded frame=%u %ux%u\n",last,width,height);
        }
        pthread_mutex_unlock(&lock);
        SDL_SetRenderDrawColor(renderer,0,0,0,255);
        SDL_RenderClear(renderer);
        if (texture) SDL_RenderCopy(renderer,texture,NULL,NULL);
        SDL_RenderPresent(renderer);
        SDL_Delay(16);
    }
    return NULL;
}
static void start_display(void) {
    pthread_t thread;
    if (pthread_create(&thread,NULL,display_thread,NULL)) { perror("display thread"); exit(1); }
    pthread_detach(thread);
}
int __wrap_sceDisplaySetFrameBuf(const SceDisplayFrameBuf *frame,SceDisplaySetBufSync sync) {
    pthread_once(&once,start_display);
    pthread_mutex_lock(&lock);
    if (frame && frame->base && frame->width && frame->height && frame->pitch>=frame->width) {
        if (frame->width>4096 || frame->height>4096) { fprintf(stderr,"invalid scanout size\n"); exit(1); }
        if (width!=frame->width || height!=frame->height) {
            free(pixels); width=frame->width; height=frame->height;
            pixels=malloc((size_t)width*height*4);
            if (!pixels) { perror("scanout allocation"); exit(1); }
        }
        for (unsigned y=0;y<height;++y)
            memcpy(pixels+(size_t)y*width*4,(uint8_t*)frame->base+(size_t)y*frame->pitch*4,width*4);
        ++serial;
    } else if (pixels) { memset(pixels,0,(size_t)width*height*4); ++serial; }
    pthread_mutex_unlock(&lock);
    return __real_sceDisplaySetFrameBuf(frame,sync);
}
int __wrap_sceCtrlPeekBufferPositive(int port,SceCtrlData *data,int count) {
    int result=__real_sceCtrlPeekBufferPositive(port,data,count);
    if (result>0 && data && count>0) {
        pthread_mutex_lock(&lock);
        data->buttons |= buttons;
        if (axes[0]!=128) data->lx=axes[0];
        if (axes[1]!=128) data->ly=axes[1];
        if (axes[2]!=128) data->rx=axes[2];
        if (axes[3]!=128) data->ry=axes[3];
        pthread_mutex_unlock(&lock);
    }
    return result;
}
