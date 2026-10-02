/* SPDX-License-Identifier: GPL-3.0-or-later
 * Optional observations only: no vertex or draw-state changes.
 */
#include <math.h>
static void h2_linux_vertex_audit(const menu_vertex_out *a,
                                  const menu_vertex_out *b,
                                  const menu_vertex_out *c)
{
    static int enabled = -1;
    static unsigned long long triangles, behind, crossing, near, far, invalid;
    static unsigned samples;
    if (enabled < 0) {
        const char *e = getenv("XV_LINUX_VERTEX_AUDIT");
        enabled = e && atoi(e) != 0;
    }
    if (!enabled) return;
    const menu_vertex_out *v[3] = {a,b,c};
    unsigned negative_w=0, negative_z=0, far_z=0, nonfinite=0;
    for (unsigned i=0;i<3;++i) {
        negative_w += v[i]->w <= 0;
        negative_z += v[i]->z < 0;
        far_z += v[i]->z > 1;
        nonfinite += !(isfinite(v[i]->x) && isfinite(v[i]->y) &&
                       isfinite(v[i]->z) && isfinite(v[i]->w));
    }
    ++triangles; behind += negative_w==3;
    crossing += negative_w>0 && negative_w<3;
    near += negative_z>0; far += far_z>0; invalid += nonfinite>0;
    if ((negative_w || nonfinite) && samples<8) {
        ++samples;
        xv_logf("[linux/vertex] sample=%u xyz_w=(%.9g,%.9g,%.9g,%.9g) (%.9g,%.9g,%.9g,%.9g) (%.9g,%.9g,%.9g,%.9g)\n",
            samples,a->x,a->y,a->z,a->w,b->x,b->y,b->z,b->w,c->x,c->y,c->z,c->w);
    }
    if (triangles%50000==0)
        xv_logf("[linux/vertex] triangles=%llu all_w_nonpositive=%llu crossing_w=%llu near_z=%llu far_z=%llu nonfinite=%llu\n",
            triangles,behind,crossing,near,far,invalid);
}
