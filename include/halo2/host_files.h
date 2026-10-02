#ifndef HALO2_HOST_FILES_H
#define HALO2_HOST_FILES_H
#include "halo2/file_io.h"
/* Native Linux adapter, not recovered game code. One context per engine thread
 * until the host threading/TLS implementation is available. Mounts name existing
 * directories; paths resolve within their mounted drive, without symlinks. */
typedef struct h2_host_files h2_host_files;
h2_host_files *h2_host_files_create(h2_memory *);
int h2_host_files_mount(h2_host_files *, char drive, const char *directory);
h2_file_platform h2_host_files_operations(h2_host_files *);
uint32_t h2_host_files_open_count(h2_host_files *);
void h2_host_files_destroy(h2_host_files *);
#endif
