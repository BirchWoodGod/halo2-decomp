#ifndef HALO2_GAME_LIFECYCLE_H
#define HALO2_GAME_LIFECYCLE_H
#include "halo2/arena.h"
/* Required external operations. Dispatch must execute the requested subsystem
 * or report failure; silently skipping an unknown function cannot boot the game.
 * Callback contexts may mutate guest memory, including the global state pointer. */
typedef struct {
    void *context;
    void (*control_fp)(void *,uint32_t value,uint32_t mask);
    void (*dispatch)(void *,uint32_t function);
    void (*validate_variant)(void *,uint32_t variant);
} h2_game_operations;
void h2_game_initialize(h2_memory *,const h2_arena_platform *,const h2_game_operations *); /* 00137c20 */
void h2_game_initialize_for_map(h2_memory *,const h2_game_operations *,uint32_t options); /* 00137ca0 */
void h2_game_dispose_from_map(h2_memory *,const h2_game_operations *); /* 00137d00 */
void h2_game_initialize_for_structure(h2_memory *,const h2_game_operations *); /* 00137d40 */
void h2_game_dispose_from_structure(h2_memory *,const h2_game_operations *); /* 00137da0 */
void h2_game_set_options(h2_memory *,const h2_game_operations *,uint32_t options); /* 00137dd0 */
#endif
