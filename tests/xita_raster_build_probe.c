/* SPDX-License-Identifier: GPL-3.0-or-later
 * Compare strict compiler configurations against the retained Xita renderer.
 * Emits complete color/depth/count results, not just checksums.
 */
#include "menu_raster.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#ifdef XITA_UNITY
#include "menu_combiner.c"
#include "menu_raster.c"
#endif
static uint32_t seed=0x58495841;
static uint32_t rng(void) { seed^=seed<<13; seed^=seed>>17; seed^=seed<<5; return seed; }
static float scalar(void) { return (float)(rng()%2048)/1024.0f-0.5f; }
int main(int argc,char **argv) {
    if(argc!=2) return 2;
    FILE *out=fopen(argv[1],"wb"); if(!out) return 2;
    uint8_t pixels[96*96*4]; uint32_t depth[96*96],texels[4][16*16];
    const uint32_t factors[]={0,1,0x300,0x301,0x302,0x303,0x304,0x305,0x306,0x307,0x308,0x8001,0x8002,0x8003,0x8004};
    const uint32_t equations[]={0x8006,0x8007,0x8008,0x800a,0x800b,0xf005,0xf006};
    clock_t begin=clock();
    for(unsigned trial=0;trial<512;++trial) {
        menu_raster_state st; memset(&st,0,sizeof st);
        menu_combiner cb; memset(&cb,0,sizeof cb);
        for(unsigned i=0;i<sizeof pixels;++i) pixels[i]=(uint8_t)rng();
        for(unsigned i=0;i<96*96;++i) depth[i]=rng();
        for(unsigned t=0;t<4;++t) {
            for(unsigned i=0;i<256;++i) texels[t][i]=rng();
            st.tex[t]=(menu_texture){texels[t],16,16,(int)(trial&1)};
        }
        st.target=(menu_target){pixels,96,96,96*4};
        st.clip_x0=trial%4;st.clip_y0=trial%3;st.clip_x1=95;st.clip_y1=95;
        st.blend=trial%3;st.sfactor=factors[rng()%15];st.dfactor=factors[rng()%15];
        st.equation=equations[rng()%7];st.blend_color=rng();
        st.alpha_test=trial%2;st.alpha_func=0x200+trial%8;st.alpha_ref=scalar();
        st.depth=(menu_depth){trial%3 ? depth : NULL,96,96,96*4,0x200+trial%8,(int)(trial%2)};
        st.zpass_count=1;menu_raster_zpass=0;
        cb.stages=trial%9;cb.mux_msb=trial%2;
        for(unsigned i=0;i<8;++i) {
            cb.rgb_in[i]=rng();cb.alpha_in[i]=rng();
            cb.rgb_out[i]=rng()&0xfffff;cb.alpha_out[i]=rng()&0xfffff;
            cb.factor0[i]=rng();cb.factor1[i]=rng();
        }
        cb.final_abcd=rng();cb.final_efg=rng();cb.final_factor0=rng();cb.final_factor1=rng();
        menu_combiner_prepare(&cb);st.combiner=trial%5 ? &cb : NULL;
        for(unsigned draw=0;draw<8;++draw) {
            menu_vertex_out v[3];memset(v,0,sizeof v);
            for(unsigned j=0;j<3;++j) {
                v[j].x=scalar()*96;v[j].y=scalar()*96;
                v[j].z=scalar();v[j].w=0.1f+(float)(rng()%1024)/512.0f;
                for(unsigned k=0;k<4;++k) {
                    v[j].color[k]=scalar();v[j].specular[k]=scalar();
                    v[j].uv[k][0]=scalar()*4;v[j].uv[k][1]=scalar()*4;
                }
            }
            menu_raster_triangle(&st,&v[0],&v[1],&v[2]);
        }
        if(fwrite(pixels,1,sizeof pixels,out)!=sizeof pixels ||
           fwrite(depth,1,sizeof depth,out)!=sizeof depth ||
           fwrite(&menu_raster_zpass,1,sizeof menu_raster_zpass,out)!=sizeof menu_raster_zpass) return 2;
    }
    fprintf(stderr,"512 cases, 4096 triangles: %.3f CPU seconds\n",(double)(clock()-begin)/CLOCKS_PER_SEC);
    return fclose(out)!=0;
}
