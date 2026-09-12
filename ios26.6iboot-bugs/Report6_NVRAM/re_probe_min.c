#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
typedef uint8_t u8; typedef uint64_t u64;
static u8 *g_fw; static size_t g_fw_sz;
typedef u64 (*fn_adler)(const void*, void*, void*, u64, u64);
typedef u8 (*fn_recsum)(const void*, void*, void*);
int main(int argc,char**argv){
  const char*p="/tmp/ds_iboot/iboot_dec.bin"; u64 A=0x158fec,R=0x1709e8;
  if(argc>1&&!strstr(argv[1],"1628")){p="/tmp/ds_iboot/23g83/iboot_dec_23g83.bin";A=0x1591a4;R=0x170ba8;}
  int fd=open(p,O_RDONLY); struct stat st; fstat(fd,&st); g_fw_sz=st.st_size;
  size_t span=(g_fw_sz+0x3fff)&~0x3fffUL;
  u8*m=mmap(NULL,span,PROT_READ|PROT_EXEC,MAP_FILE|MAP_PRIVATE,fd,0); close(fd);
  fprintf(stderr,"[probe] mapped %p sz=%zu adler=%llx recsum=%llx\n",m,span,(unsigned long long)A,(unsigned long long)R);
  u8 buf[4096]; memset(buf,0x33,sizeof buf); buf[0]=0x71;
  fprintf(stderr,"[probe] about to recsum\n");
  fflush(stderr);
  u8 s=((fn_recsum)(m+R))(buf,buf,buf+sizeof buf+0x100);
  fprintf(stderr,"[probe] recsum -> %02x\n",s); fflush(stderr);
  fprintf(stderr,"[probe] about to adler\n"); fflush(stderr);
  u64 a=((fn_adler)(m+A))(buf+0x14,buf,buf+sizeof buf+0x100,0,sizeof buf-0x14);
  fprintf(stderr,"[probe] adler -> %08llx\n",(unsigned long long)a); fflush(stderr);
  /* repeat x1000 determinism */
  u8 s2=0; for(int i=0;i<1000;i++) s2=((fn_recsum)(m+R))(buf,buf,buf+sizeof buf+0x100);
  u64 a2=0; for(int i=0;i<100;i++) a2=((fn_adler)(m+A))(buf+0x14,buf,buf+sizeof buf+0x100,0,sizeof buf-0x14);
  fprintf(stderr,"[probe] det: recsum=%02x adler=%08llx stable=%d/%d\n",s2,(unsigned long long)a2,s2==s,a2==a);
  return 0;
}
