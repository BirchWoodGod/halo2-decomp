#define _POSIX_C_SOURCE 200809L
#include "halo2/host_files.h"
#include "internal/memory.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum { HANDLE_COUNT = 256 };
typedef struct {
    int fd, parent;
    uint32_t access, sharing;
    dev_t device;
    ino_t inode;
    char name[256];
} host_handle;
struct h2_host_files {
    h2_memory *memory;
    int drives[26];
    host_handle handles[HANDLE_COUNT];
    uint32_t error;
};

static unsigned fold(unsigned c) { return c >= 'A' && c <= 'Z' ? c+32 : c; }
static int same_name(const char *a, const char *b) {
    while (*a && fold((unsigned char)*a) == fold((unsigned char)*b)) { ++a; ++b; }
    return !*a && !*b;
}
static uint32_t error_number(int error) {
    switch (error) {
        case ENOENT: return 2;
        case ENOTDIR: return 3;
        case EACCES: case EPERM: case ELOOP: return 5;
        case EBADF: return 6;
        case EMFILE: case ENFILE: return 4;
        case ENOSPC: return 112;
        case EINVAL: case EOVERFLOW: return 87;
        default: return 31;
    }
}
static void system_error(h2_host_files *h) { h->error = error_number(errno); }

/* Prefer exact spelling, otherwise require a unique ASCII-insensitive match. */
static int find_name(int parent, const char *requested, char output[256]) {
    struct stat st;
    if (!fstatat(parent, requested, &st, AT_SYMLINK_NOFOLLOW)) {
        strcpy(output, requested);
        return 1;
    }
    int fd = openat(parent, ".", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    if (fd < 0) return 0;
    DIR *directory = fdopendir(fd);
    if (!directory) { close(fd); return 0; }
    int found = 0;
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        if (same_name(requested, entry->d_name)) {
            if (found) { found = -1; break; }
            strcpy(output, entry->d_name);
            found = 1;
        }
    }
    closedir(directory);
    if (found != 1) { errno = found ? EINVAL : ENOENT; return 0; }
    return 1;
}

/* Resolve all parent components by descriptor. Return owned parent descriptor
 * and final spelling; never interpret a guest path relative to host cwd. */
static int resolve(h2_host_files *h, const uint8_t path[256], char final[256]) {
    size_t n = strnlen((const char *)path, 256);
    unsigned drive = fold(path[0]);
    if (n < 3 || n == 256 || drive < 'a' || drive > 'z' || path[1] != ':' || path[2] != '\\') {
        h->error = 123; return -1;
    }
    if (h->drives[drive-'a'] < 0) { h->error = 15; return -1; }
    char copy[256];
    memcpy(copy, path+3, n-2);
    for (char *p = copy; *p; ++p) if (*p == '\\') *p = '/';
    int dirs[128], depth = 0;
    dirs[0] = dup(h->drives[drive-'a']);
    if (dirs[0] < 0) { system_error(h); return -1; }
    char *state = NULL, *part = strtok_r(copy, "/", &state);
    while (part) {
        char *next = strtok_r(NULL, "/", &state);
        if (!strcmp(part,".")) { part = next; continue; }
        if (!strcmp(part,"..")) {
            if (!depth) { h->error = 5; goto fail; }
            close(dirs[depth--]); part = next; continue;
        }
        if (!find_name(dirs[depth], part, final)) { system_error(h); goto fail; }
        if (!next) {
            int result = dirs[depth];
            while (depth) close(dirs[--depth]);
            return result;
        }
        int fd = openat(dirs[depth], final, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        if (fd < 0) { system_error(h); goto fail; }
        dirs[++depth] = fd;
        part = next;
    }
    strcpy(final,".");
    { int result = dirs[depth]; while (depth) close(dirs[--depth]); return result; }
fail:
    do { close(dirs[depth]); } while (depth--);
    return -1;
}

static int query(h2_host_files *h, const uint8_t *path, struct stat *st) {
    char name[256]; int parent = resolve(h,path,name);
    if (parent < 0) return 0;
    int result = fstatat(parent,name,st,AT_SYMLINK_NOFOLLOW);
    if (result < 0) system_error(h);
    close(parent);
    if (result < 0) return 0;
    if (S_ISLNK(st->st_mode)) { h->error = 5; return 0; }
    return 1;
}
static uint32_t attributes(void *context, const uint8_t *path) {
    h2_host_files *h=context; struct stat st;
    if (!query(h,path,&st)) return UINT32_MAX;
    return S_ISDIR(st.st_mode) ? 0x10 : 0x80;
}
static void put32(uint8_t *p, uint32_t x) {
    for (unsigned i=0;i<4;++i) p[i]=(uint8_t)(x>>(8*i));
}
static uint32_t metadata(void *context, const uint8_t *path, uint32_t level, uint8_t *info) {
    h2_host_files *h=context; struct stat st;
    if (level) { h->error=87; return 0; }
    if (!query(h,path,&st)) return 0;
    memset(info,0,36);
    put32(info,S_ISDIR(st.st_mode) ? 0x10 : 0x80);
    put32(info+28,(uint32_t)((uint64_t)st.st_size>>32));
    put32(info+32,(uint32_t)st.st_size);
    /* The recovered caller consumes size only. Timestamp translation remains
     * outstanding; no metadata-time fidelity is claimed. */
    return 1;
}
static uint32_t open_file(void *context, const uint8_t *path, uint32_t access,
    uint32_t sharing, uint32_t security, uint32_t disposition, uint32_t flags, uint32_t template_handle) {
    h2_host_files *h=context;
    if (security || template_handle || disposition!=3 || (access&0x3fffffff) || (sharing&~3u)) {
        h->error=87; return UINT32_MAX;
    }
    unsigned slot;
    for (slot=0;slot<HANDLE_COUNT && h->handles[slot].fd>=0;++slot) {}
    if (slot==HANDLE_COUNT) { h->error=4; return UINT32_MAX; }
    char name[256]; int parent=resolve(h,path,name);
    if (parent<0) return UINT32_MAX;
    int mode=(access&0x40000000) ? ((access&0x80000000) ? O_RDWR : O_WRONLY) : O_RDONLY;
    int fd=openat(parent,name,mode|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) { system_error(h); close(parent); return UINT32_MAX; }
    struct stat st;
    if (fstat(fd,&st)<0) { system_error(h); close(fd); close(parent); return UINT32_MAX; }
    if (!S_ISREG(st.st_mode)) { h->error=5; close(fd); close(parent); return UINT32_MAX; }
    uint32_t bits=((access>>31)&1)|((access>>29)&2);
    for (unsigned i=0;i<HANDLE_COUNT;++i) {
        host_handle *old=&h->handles[i];
        if (old->fd>=0 && old->device==st.st_dev && old->inode==st.st_ino &&
            ((bits&~old->sharing) || (old->access&~sharing))) {
            h->error=32; close(fd); close(parent); return UINT32_MAX;
        }
    }
    host_handle *entry=&h->handles[slot];
    entry->fd=fd; entry->access=bits; entry->sharing=sharing;
    entry->device=st.st_dev; entry->inode=st.st_ino;
    entry->parent=(flags&0x4000000) ? parent : -1;
    strcpy(entry->name,name);
    if (entry->parent<0) close(parent);
    if (flags&0x8000000) (void)posix_fadvise(fd,0,0,POSIX_FADV_SEQUENTIAL);
    else if (flags&0x10000000) (void)posix_fadvise(fd,0,0,POSIX_FADV_RANDOM);
    return slot+1;
}
static host_handle *lookup(h2_host_files *h, uint32_t handle) {
    if (!handle || handle>HANDLE_COUNT || h->handles[handle-1].fd<0) { h->error=6; return NULL; }
    return &h->handles[handle-1];
}
static uint32_t transfer(h2_host_files *h,uint32_t handle,uint32_t buffer,uint32_t count,uint32_t *done,int writing) {
    *done=0; host_handle *entry=lookup(h,handle);
    if (!entry) return 0;
    if (!(entry->access&(writing ? 2u : 1u))) { h->error=5; return 0; }
    uint8_t *bytes=h2_ptr(h->memory,buffer,count);
    ssize_t result;
    do { result=writing ? write(entry->fd,bytes,count) : read(entry->fd,bytes,count); } while (result<0 && errno==EINTR);
    if (result<0) { system_error(h); return 0; }
    *done=(uint32_t)result; return 1;
}
static uint32_t read_file(void *h,uint32_t f,uint32_t b,uint32_t n,uint32_t *done) { return transfer(h,f,b,n,done,0); }
static uint32_t write_file(void *h,uint32_t f,uint32_t b,uint32_t n,uint32_t *done) { return transfer(h,f,b,n,done,1); }
static uint32_t seek_file(void *context,uint32_t handle,uint32_t position,uint32_t high,uint32_t origin) {
    h2_host_files *h=context; host_handle *entry=lookup(h,handle);
    if (!entry) return UINT32_MAX;
    if (high || origin>2) { h->error=87; return UINT32_MAX; }
    int64_t displacement=position<=INT32_MAX ? (int64_t)position : (int64_t)position-INT64_C(0x100000000);
    off_t result=lseek(entry->fd,(off_t)displacement,origin==0 ? SEEK_SET : origin==1 ? SEEK_CUR : SEEK_END);
    if (result<0) { system_error(h); return UINT32_MAX; }
    return (uint32_t)result;
}
static uint32_t set_end(void *context,uint32_t handle) {
    h2_host_files *h=context; host_handle *entry=lookup(h,handle);
    if (!entry) return 0;
    if (!(entry->access&2)) { h->error=5; return 0; }
    off_t position=lseek(entry->fd,0,SEEK_CUR);
    if (position<0 || ftruncate(entry->fd,position)<0) { system_error(h); return 0; }
    return 1;
}
static uint32_t close_file(void *context,uint32_t handle) {
    h2_host_files *h=context; host_handle *entry=lookup(h,handle);
    if (!entry) return 0;
    int ok=1;
    if (entry->parent>=0) {
        struct stat st;
        if (fstatat(entry->parent,entry->name,&st,AT_SYMLINK_NOFOLLOW)<0 ||
            st.st_dev!=entry->device || st.st_ino!=entry->inode) { h->error=5; ok=0; }
        else if (unlinkat(entry->parent,entry->name,0)<0) { system_error(h); ok=0; }
        close(entry->parent); entry->parent=-1;
    }
    if (close(entry->fd)<0) { system_error(h); ok=0; }
    entry->fd=-1;
    return (uint32_t)ok;
}
static uint32_t last_error(void *context) { return ((h2_host_files *)context)->error; }
static void set_error(void *context,uint32_t error) { ((h2_host_files *)context)->error=error; }

h2_host_files *h2_host_files_create(h2_memory *memory) {
    h2_host_files *h=calloc(1,sizeof(*h)); if (!h) return NULL;
    h->memory=memory;
    for (unsigned i=0;i<26;++i) h->drives[i]=-1;
    for (unsigned i=0;i<HANDLE_COUNT;++i) h->handles[i].fd=h->handles[i].parent=-1;
    return h;
}
int h2_host_files_mount(h2_host_files *h,char drive,const char *directory) {
    unsigned d=fold((unsigned char)drive);
    if (d<'a' || d>'z') { h->error=15; return 0; }
    int fd=open(directory,O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    if (fd<0) { system_error(h); return 0; }
    if (h->drives[d-'a']>=0) close(h->drives[d-'a']);
    h->drives[d-'a']=fd; return 1;
}
h2_file_platform h2_host_files_operations(h2_host_files *h) {
    h2_file_platform ops={h,read_file,write_file,close_file,last_error,set_error,seek_file,set_end,attributes,metadata,open_file};
    return ops;
}
uint32_t h2_host_files_open_count(h2_host_files *h) {
    uint32_t n=0; for (unsigned i=0;i<HANDLE_COUNT;++i) n+=h->handles[i].fd>=0; return n;
}
void h2_host_files_destroy(h2_host_files *h) {
    if (!h) return;
    for (unsigned i=0;i<HANDLE_COUNT;++i) if (h->handles[i].fd>=0) (void)close_file(h,i+1);
    for (unsigned i=0;i<26;++i) if (h->drives[i]>=0) close(h->drives[i]);
    free(h);
}
