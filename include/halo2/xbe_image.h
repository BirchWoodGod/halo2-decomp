#ifndef HALO2_XBE_IMAGE_H
#define HALO2_XBE_IMAGE_H
#include "halo2/heap.h"
/* Host-side image mapper. It copies data but does not execute Xbox machine code.
 * Requires an empty heap with base 0x10000, enough room for the pinned image.
 * The image allocation remains live and must never be handed to engine free. */
int h2_xbe_load(h2_heap *, const char *path, char *error, size_t error_size);
#endif
