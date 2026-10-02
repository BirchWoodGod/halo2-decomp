/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "menu_raster.h"
#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
void h2_linux_clip_triangle(const menu_raster_state *,const menu_vertex_out *,const menu_vertex_out *,const menu_vertex_out *);
static menu_vertex_out emitted[48];static unsigned count;
void menu_raster_triangle(const menu_raster_state *s,const menu_vertex_out *a,const menu_vertex_out *b,const menu_vertex_out *c) {
    const menu_vertex_out *v[]={a,b,c};
    for(unsigned i=0;i<3;++i) {
        assert(count<48);emitted[count++]=*v[i];
        assert(isfinite(v[i]->x)&&isfinite(v[i]->y)&&isfinite(v[i]->z)&&isfinite(v[i]->w));
        assert(v[i]->x>=-0.001f && v[i]->x<=s->target.width+0.001f);
        assert(v[i]->y>=-0.001f && v[i]->y<=s->target.height+0.001f);
        assert(v[i]->z>=-0.00001f && v[i]->z<=1.00001f && v[i]->w>0);
    }
}
static menu_vertex_out vertex(float x,float y,float z,float w,float color) {
    menu_vertex_out v;memset(&v,0,sizeof v);v.x=x;v.y=y;v.z=z;v.w=w;
    for(unsigned k=0;k<4;++k) {v.color[k]=color;v.specular[k]=color*2;v.uv[k][0]=color*3;v.uv[k][1]=color*4;}
    return v;
}
static void run(menu_raster_state *s,menu_vertex_out a,menu_vertex_out b,menu_vertex_out c) {
    count=0;h2_linux_clip_triangle(s,&a,&b,&c);
}
int main(void) {
    menu_raster_state s;memset(&s,0,sizeof s);s.target.width=s.target.height=64;
    menu_vertex_out a=vertex(10,10,.5,1,0),b=vertex(30,10,.5,3,1),c=vertex(10,30,.5,3,1);
    run(&s,a,b,c);assert(count==3);
    assert(!memcmp(&a,&emitted[0],sizeof a)&&!memcmp(&b,&emitted[1],sizeof b)&&!memcmp(&c,&emitted[2],sizeof c));
    a.w=b.w=c.w=-1;run(&s,a,b,c);assert(!count);
    a=vertex(-10,10,.5,1,0);b=vertex(10,10,.5,3,1);c=vertex(10,30,.5,3,1);
    run(&s,a,b,c);assert(count==6);unsigned edges=0;
    for(unsigned i=0;i<count;++i) if(fabsf(emitted[i].x)<1e-5f) {
        ++edges;assert(fabsf(emitted[i].w-1.5f)<1e-5f);
        assert(fabsf(emitted[i].color[0]-.25f)<1e-5f);
        assert(fabsf(emitted[i].specular[0]-.5f)<1e-5f);
        assert(fabsf(emitted[i].uv[0][0]-.75f)<1e-5f);
        assert(fabsf(emitted[i].uv[0][1]-1)<1e-5f);
    }
    assert(edges>=2);
    a=vertex(10,10,-1,1,0);b=vertex(30,10,1,1,1);c=vertex(10,30,1,1,1);
    run(&s,a,b,c);assert(count==6);edges=0;
    for(unsigned i=0;i<count;++i) if(fabsf(emitted[i].z)<1e-5f) {
        ++edges;assert(fabsf(emitted[i].color[0]-.5f)<1e-5f);
    }
    assert(edges>=2);
    a.z=b.z=c.z=-1;run(&s,a,b,c);assert(!count);
    a.z=b.z=c.z=2;run(&s,a,b,c);assert(!count);
    a=vertex(10,10,2,-1,0);b=vertex(30,10,.5,1,1);c=vertex(10,30,.5,1,1);
    run(&s,a,b,c);assert(count>=3);
    a.x=NAN;run(&s,a,b,c);assert(!count);
    unsigned seed=12345;
    for(unsigned n=0;n<4096;++n) {
        menu_vertex_out v[3];
        for(unsigned i=0;i<3;++i) {
            float p[4];for(unsigned k=0;k<4;++k) {seed=seed*1664525u+1013904223u;p[k]=(float)(seed%128)-32;}
            v[i]=vertex(p[0],p[1],p[2]/32,p[3]/16,0.5);
        }
        run(&s,v[0],v[1],v[2]);
    }
    puts("clip: analytic interpolation, rejection, identity and 4096 bounded-output cases passed");
}
