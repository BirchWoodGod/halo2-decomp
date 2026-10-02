/* SPDX-License-Identifier: GPL-3.0-or-later
 * Experimental clipping for Xita's post-viewport software vertices.
 * Reconstruct homogeneous window coordinates, clip, then divide again.
 * This assumes the standard 0..1 depth range used by menu_render.c.
 */
#include "menu_raster.h"
#include <math.h>
#include <string.h>

typedef struct {
    double p[4];
    double color[4], specular[4], uv[4][2];
} clip_vertex;

static double distance_to_plane(const clip_vertex *v, unsigned plane, double width, double height)
{
    switch (plane) {
    /* Positive w guard avoids undefined projection at the clip-cone apex.
     * Deliberately explicit experimental tolerance, not a hardware claim. */
    case 0: return v->p[3]-1e-6;
    case 1: return v->p[0];
    case 2: return width*v->p[3]-v->p[0];
    case 3: return v->p[1];
    case 4: return height*v->p[3]-v->p[1];
    case 5: return v->p[2];
    default: return v->p[3]-v->p[2];
    }
}

static clip_vertex interpolate(const clip_vertex *a,const clip_vertex *b,double t)
{
    clip_vertex v;
    for(unsigned k=0;k<4;++k) {
        v.p[k]=a->p[k]+t*(b->p[k]-a->p[k]);
        v.color[k]=a->color[k]+t*(b->color[k]-a->color[k]);
        v.specular[k]=a->specular[k]+t*(b->specular[k]-a->specular[k]);
        for(unsigned j=0;j<2;++j) v.uv[k][j]=a->uv[k][j]+t*(b->uv[k][j]-a->uv[k][j]);
    }
    return v;
}

void h2_linux_clip_triangle(const menu_raster_state *st, const menu_vertex_out *a,
                           const menu_vertex_out *b,const menu_vertex_out *c)
{
    const menu_vertex_out *input[3]={a,b,c};
    int inside=1;
    for(unsigned i=0;i<3;++i) {
        const menu_vertex_out *v=input[i];
        if(!isfinite(v->x)||!isfinite(v->y)||!isfinite(v->z)||!isfinite(v->w)) return;
        inside &= v->w>=1e-6f && v->x>=0 && v->x<=st->target.width &&
                  v->y>=0 && v->y<=st->target.height && v->z>=0 && v->z<=1;
    }
    if(inside) { menu_raster_triangle(st,a,b,c); return; }
    if(a->w<=0 && b->w<=0 && c->w<=0) return;
    clip_vertex buffers[2][16];
    for(unsigned i=0;i<3;++i) {
        clip_vertex *v=&buffers[0][i]; const menu_vertex_out *s=input[i];
        v->p[0]=(double)s->x*s->w;v->p[1]=(double)s->y*s->w;
        v->p[2]=(double)s->z*s->w;v->p[3]=s->w;
        for(unsigned k=0;k<4;++k) {
            v->color[k]=s->color[k];v->specular[k]=s->specular[k];
            for(unsigned j=0;j<2;++j) v->uv[k][j]=s->uv[k][j];
        }
    }
    unsigned count=3,current=0;
    for(unsigned plane=0;plane<7 && count;++plane) {
        clip_vertex *src=buffers[current],*dst=buffers[current^1];unsigned next=0;
        for(unsigned i=0;i<count;++i) {
            const clip_vertex *s=&src[i],*e=&src[(i+1)%count];
            double ds=distance_to_plane(s,plane,st->target.width,st->target.height);
            double de=distance_to_plane(e,plane,st->target.width,st->target.height);
            if((ds>=0)!=(de>=0)) {
                if(next>=16) return;
                dst[next]=interpolate(s,e,ds/(ds-de));
                if(plane==0) dst[next].p[3]=1e-6;
                ++next;
            }
            if(de>=0) { if(next>=16) return; dst[next++]=*e; }
        }
        current^=1;count=next;
    }
    menu_vertex_out projected[16];memset(projected,0,sizeof projected);
    for(unsigned i=0;i<count;++i) {
        const clip_vertex *v=&buffers[current][i];menu_vertex_out *d=&projected[i];
        if(!(v->p[3]>0)) return;
        d->x=(float)(v->p[0]/v->p[3]);d->y=(float)(v->p[1]/v->p[3]);
        d->z=(float)(v->p[2]/v->p[3]);d->w=(float)v->p[3];
        for(unsigned k=0;k<4;++k) {
            d->color[k]=(float)v->color[k];d->specular[k]=(float)v->specular[k];
            for(unsigned j=0;j<2;++j) d->uv[k][j]=(float)v->uv[k][j];
        }
    }
    for(unsigned i=1;i+1<count;++i) menu_raster_triangle(st,&projected[0],&projected[i],&projected[i+1]);
}
