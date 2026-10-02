#include "halo2/xbe_image.h"
#include "halo2/engine_pools.h"
#include "halo2/data_array.h"
#include "halo2/hash_table.h"
#include "halo2/arena.h"
#include "halo2/online_tasks.h"
#include "halo2/host_files.h"
#include "halo2/network_config.h"
#include "internal/memory.h"
#include <stdio.h>
#include <string.h>

static uint32_t arena_backing(void *context,uint32_t primary,uint32_t extra) {
    return h2_heap_allocate(context,primary+extra);
}
/* This diagnostic does not load/save games. The real service is outstanding. */
static void diagnostic_save_storage(void *context) { (void)context; }

static int probe_configuration(const char *xbe, const char *directory) {
    h2_heap *heap=h2_heap_create(0x10000,64*1024*1024-0x10000);
    if (!heap) return 1;
    char error[200];
    if (!h2_xbe_load(heap,xbe,error,sizeof(error))) {
        fprintf(stderr,"%s\n",error);h2_heap_destroy(heap);return 1;
    }
    h2_memory *m=h2_heap_memory(heap);
    h2_host_files *files=h2_host_files_create(m);
    uint32_t workspace=h2_heap_allocate(heap,0x114);
    if (!files || !workspace || !h2_host_files_mount(files,'z',directory)) {
        fputs("Cannot prepare the configuration workspace or mount cache directory\n",stderr);
        h2_host_files_destroy(files);h2_heap_destroy(heap);return 1;
    }
    h2_file_platform ops=h2_host_files_operations(files);
    int valid=h2_network_config_load(m,&ops,workspace);
    int clean=h2_host_files_open_count(files)==0;
    if (valid) printf("Configuration loaded through native Linux I/O: version=%u records=%u\n",
        h2_read32(m,0x4cf970),h2_read32(m,0x4cf978));
    else fputs("Configuration missing, unreadable, or rejected by recovered validation\n",stderr);
    if (!clean) fputs("Configuration probe leaked a file handle\n",stderr);
    h2_host_files_destroy(files);
    h2_heap_destroy(heap);
    return valid && clean ? 0 : 1;
}

/* First native host bring-up: only the explicitly named engine pool probe.
 * This does not boot the game, display a menu, or execute original x86 code. */
int main(int argc,char **argv) {
    if (argc==4 && !strcmp(argv[1],"--probe-config"))
        return probe_configuration(argv[2],argv[3]);
    if (argc!=3 || strcmp(argv[1],"--probe-pools")) {
        fprintf(stderr,"Usage: %s --probe-pools /path/to/default.xbe\n"
            "       %s --probe-config /path/to/default.xbe /path/to/cache-directory\n"
            "Native engine probes; game boot is not implemented yet.\n",argv[0],argv[0]);
        return 2;
    }
    h2_heap *heap=h2_heap_create(0x10000,64*1024*1024-0x10000);
    if (!heap) { fputs("Cannot allocate host guest-memory arena\n",stderr);return 1; }
    char error[200];
    if (!h2_xbe_load(heap,argv[2],error,sizeof(error))) {
        fprintf(stderr,"%s\n",error);h2_heap_destroy(heap);return 1;
    }
    h2_memory *m=h2_heap_memory(heap);
    h2_allocator ops=h2_heap_allocator(heap);
    uint32_t identity=h2_heap_allocate(heap,16);
    if (!identity) { h2_heap_destroy(heap);return 1; }
    h2_write32(m,0x468758,identity);
    h2_arena_platform platform={heap,arena_backing,diagnostic_save_storage,NULL,diagnostic_save_storage};
    h2_arena_initialize(m,&platform);
    uint32_t arena=h2_read32(m,0x4e6080);
    h2_allocator arena_ops=h2_arena_allocator(m);
    h2_command_scripts_initialize(m,&arena_ops);
    h2_havok_components_initialize(m,&ops);
    h2_actors_initialize(m,&arena_ops);
    h2_online_tasks_initialize(m,&ops);
    const uint32_t globals[]={0x502408,0x502404,0x51e9b8,0x4f55f0,0x4cf78c};
    for (unsigned i=0;i<5;i++) {
        uint32_t a=h2_read32(m,globals[i]);
        if (!a) { fputs("Engine pool allocation failed\n",stderr);h2_heap_destroy(heap);return 1; }
        h2_data_activate(m,a);
        uint32_t handle=h2_data_new(m,a);
        if (handle==H2_NONE || !h2_data_get(m,a,handle)) {
            fputs("Native engine pool smoke test failed\n",stderr);h2_heap_destroy(heap);return 1;
        }
        h2_data_delete(m,a,handle);
        printf("%s: capacity=%u stride=%u native allocation/lookup/delete passed\n",
            (char *)h2_ptr(m,a,32),h2_read32(m,a+0x20),h2_read32(m,a+0x24));
        if (i==4) {
            /* The probe has deleted its only task; shutdown needs no SDK calls. */
            const h2_online_task_platform online={0};
            h2_online_tasks_dispose(m,&ops,&online);
        } else h2_data_dispose(m,i==2 ? &ops : &arena_ops,a);
        h2_write32(m,globals[i],0);
    }
    uint32_t owners=h2_read32(m,0x557c6c);
    h2_key_ops keys=h2_actor_owner_key_ops();
    h2_write32(m,identity+4,0x12345678);
    if (!owners || h2_read32(m,0x4f93a0)<arena ||
        h2_read32(m,0x4f93a0)+0x640>arena+h2_read32(m,0x4e6084) ||
        !h2_hash_insert(m,&keys,owners,256,identity+4)) {
        fputs("Actor owner initialization failed\n",stderr);h2_heap_destroy(heap);return 1;
    }
    uint32_t node=h2_hash_find(m,&keys,owners,256);
    if (!node || h2_read32(m,node+12)!=0x12345678 ||
        !h2_hash_remove(m,&keys,owners,256) || h2_hash_find(m,&keys,owners,256)) {
        fputs("Actor owner lookup failed\n",stderr);h2_heap_destroy(heap);return 1;
    }
    puts("Actor firing-position owners: native insertion/lookup/removal passed");
    printf("Recovered arena startup: %u bytes reserved; save-file setup is not implemented\n",
        h2_read32(m,0x4e6084));
    h2_arena_dispose(m,&platform);
    if (!h2_heap_release(heap,arena) ||
        !h2_heap_release(heap,identity) || h2_heap_live_allocations(heap)!=1) {
        fputs("Unexpected live engine allocations\n",stderr);h2_heap_destroy(heap);return 1;
    }
    puts("Pinned XBE mapped; native engine pool probe passed. Game boot is not implemented.");
    h2_heap_destroy(heap);
    return 0;
}
