/*

Sandal, $Revision: 0.5 $

###############################################################################
#   Subscribes to Mac OS X 10.4 fsevents and displays all filesystem changes  #
#   in a handy XML format.                                                    #
#                                                                             #
#   Copyright (C) 2005 Matterform Media [daniel at matterform dot com]        #
#                                                                             #
#   Special thanks to Rian Hunter for gfslogger, from which sandal is         #
#   derived. For more information about gfslogger, please see Rian's          #
#   site: http://rian.merseine.nu/gfslogger/                                  #                                 #
#                                                                             #
#   This program is free software; you can redistribute it and/or modify      #
#   it under the terms of the GNU General Public License as published by      #
#   the Free Software Foundation; either version 2 of the License, or         #
#   (at your option) any later version.                                       #
#                                                                             #
#   This program is distributed in the hope that it will be useful,           #
#   but WITHOUT ANY WARRANTY; without even the implied warranty of            #
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             #
#   GNU General Public License for more details.                              #
#                                                                             #
#   You should have received a copy of the GNU General Public License         #
#   along with this program; if not, write to the Free Software	            #
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA #
#                                                                             #
###############################################################################
*/
// for open(2)
#include <fcntl.h>

// for ioctl(2)
#include <sys/ioctl.h>
#include <sys/sysctl.h>

// for read(2)
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

// for printf(3)
#include <stdio.h>

// for exit(3)
#include <stdlib.h>

// for strncpy(3)
#include <string.h>

// for getpwuid(3)
#include <pwd.h>

// for getgrgid(3)
#include <grp.h>

// for S_IS*(3)
#include <sys/stat.h>

// for filesystem path limit
#include <limits.h>

// duh.
#include "fsevents.h"

// borrowed from Hypermail, for string concatenation
#define INIT_PUSH(x) memset(&(x), 0, sizeof(struct Push))
#define RETURN_PUSH(x) return (x).string
#define PUSH_STRING(x) (x).string
#define PUSH_DEFAULT PATH_MAX		/* default strings are this big */

struct Push {
    char *string;
    size_t len;
    size_t alloc;
};

/*
** Push a limited string onto a buffer, and realloc the buffer if needed.
**
** Returns the (new) buffer pointer.
*/
char *PushNString(struct Push *push, const char *append,/* string to append */
		  int size)
{				/* maximum number of bytes to copy */
    char *string = NULL;
#if 1
    if (!push)
	return NULL;		/* this is a sever error */
    if (!push->string) {
	push->string = (char *)malloc(PUSH_DEFAULT + size);
	if (!push->string)
	    return NULL;	/* error again */
	push->alloc = PUSH_DEFAULT + size;
	push->len = 0;
#ifdef DEBUG_PUSH
	fprintf(stderr, "PUSH: INIT at index 0 alloc %d\n", PUSH_DEFAULT);
#endif
    }
    else if ((push->len + size + 1) >= push->alloc) {
	char *newptr;
	push->alloc = 2*push->alloc + size;	/* enlarge the alloc size */
	newptr = (char *)realloc(push->string, push->alloc);	/* double the size */
	if (!newptr) {
	    return push->string;	/* live on the old one! */
	}
	push->string = newptr;	/* use the new buffer */
#ifdef DEBUG_PUSH
	fprintf(stderr,
		"PUSH: REALLOC at index %d to alloc %d\n", push->len,
		push->alloc);
#endif
    }
#ifdef DEBUG_PUSH
    fprintf(stderr, "PUSH: WRITE '%s' at index %d\n", append, push->len);
#endif
    strncpy(push->string + push->len, append, size);
    push->len += size;
    push->string[push->len] = 0;

    string = push->string;	/* current buffer */

#else
    while (*append && size--) {	/* continue until zero termination */
	string = PushByte(push, *append);
	append++;		/* get next character */
    }
#endif

    return string;		/* this is the new buffer */
}

/*
** Push a string onto a buffer, and realloc the buffer if needed.
**
** Returns the (new) buffer pointer.
*/
char *PushString(struct Push *push, const char *append)
{				/* string to append */
    char *string = NULL;

#if 1
    return PushNString(push, append, strlen(append));
#else
    while (*append) {		/* continue until zero termination */
	string = PushByte(push, *append);
	append++;		/* get next character */
    }
#endif
    return string;		/* this is the new buffer */
}


/* Given a string, replaces all instances of "oldpiece" with "newpiece".
**
** Modified this routine to eliminate recursion and to avoid infinite
** expansion of string when newpiece contains oldpiece.  --Byron Darrah
**
** 1998-11-17 (Daniel) modified to deal with any length strings and dynamic
** buffers.
*/

char *replace(char *string, char *oldpiece, char *newpiece)
{
    int str_index, newstr_index, oldpiece_index, end,
	new_len, old_len, cpy_len;
    char *c;

    struct Push buff;

    INIT_PUSH(buff);

    if ((c = (char *)strstr(string, oldpiece)) == NULL) {
	/* push the whole thing */
	PushString(&buff, string);
	RETURN_PUSH(buff);
    }

    new_len = strlen(newpiece);
    old_len = strlen(oldpiece);
    end = strlen(string) - old_len;
    oldpiece_index = c - string;

    newstr_index = 0;
    str_index = 0;
    while (str_index <= end && c != NULL) {
	/* Copy characters from the left of matched pattern occurence */
	cpy_len = oldpiece_index - str_index;
	PushNString(&buff, string + str_index, cpy_len);

	newstr_index += cpy_len;
	str_index += cpy_len;

	/* Copy replacement characters instead of matched pattern */

	PushString(&buff, newpiece);

	newstr_index += new_len;
	str_index += old_len;

	/* Check for another pattern match */
	if ((c = (char *)strstr(string + str_index, oldpiece)) != NULL)
	    oldpiece_index = c - string;
    }
    /* Copy remaining characters from the right of last matched pattern */
    PushString(&buff, string + str_index);

    RETURN_PUSH(buff);
}

// end borrowing from Hypermail

// wrote this to get me the XML-safe version of a string
char *xmlout(char *in)
{
   char *part1, *part2, *part3;
   
   part1 = replace(in, "&", "&amp;");
   part2 = replace(part1, "<", "&lt;");
   part3 = replace(part2, ">", "&gt;");
   
   // free some memory
   free(part1);
   free(part2);
   
   return part3;
}

// this is just helpful because it frees memory. it's nice when we do that, you know?
void xmlprintf(char *format, char *arg)
{
   // get the output-safe version
   char *newArg = xmlout(arg);
   
   // output it
   printf(format, newArg);
   
   // free the memory
   free(newArg);
}

static void die(int);
static void process_event_data(void *, int);
static void get_process_name(pid_t, char *, int);
static void get_mode_string(int32_t, char *);
static char *get_vnode_type(int32_t);
void handle_commandline_options(int argc, char *argv[]);

char large_buf[0x2000];

// a variable for the global event count
int global_event_counter = 0;

// some variables for controlling what we bother to look up
int lookup_owner_name, lookup_group_name, lookup_process_name;
char *hex_output_prefix = "0x";

// activates self as fsevent listener and displays fsevents
// must be run as root!! (at least on Mac OS X 10.4)
int main(int argc, char *argv[]) {
  int newfd, fd, n;
  signed char event_list[FSE_MAX_EVENTS];
  fsevent_clone_args retrieve_ioctl;

  // handle the options
  handle_commandline_options(argc, argv);

  event_list[FSE_CREATE_FILE]         = FSE_REPORT;
  event_list[FSE_DELETE]              = FSE_REPORT;
  event_list[FSE_STAT_CHANGED]        = FSE_REPORT;
  event_list[FSE_RENAME]              = FSE_REPORT;
  event_list[FSE_CONTENT_MODIFIED]    = FSE_REPORT;
  event_list[FSE_EXCHANGE]            = FSE_REPORT;
  event_list[FSE_FINDER_INFO_CHANGED] = FSE_REPORT;
  event_list[FSE_CREATE_DIR]          = FSE_REPORT;
  event_list[FSE_CHOWN]               = FSE_REPORT;

  fd = open("/dev/fsevents", 0, 2);
  if (fd < 0)
    die(1);

  retrieve_ioctl.event_list = event_list;
  retrieve_ioctl.num_events = sizeof(event_list);
  retrieve_ioctl.event_queue_depth = 0x400;
  retrieve_ioctl.fd = &newfd;

  if (ioctl(fd, FSEVENTS_CLONE, &retrieve_ioctl) < 0) {
    die(1);
  }

  close(fd);

  // it's important that we not actually print anything not in XML the format
  // until we get to the streaming portion
  // printf("gfslogger ready\n");
  printf("<?xml version=\"1.0\" ?>\n");
  printf("<filesystem-log>\n");

  // note: you must read at least 2048 bytes at a time on this fd, to get data.
  // also you read quick! newer events can be lost in the internal kernel event
  // buffer if you take too long to get events. thats why buffer is so large:
  // less read calls.
  while ((n = read(newfd, large_buf, sizeof(large_buf))) > 0) {
    process_event_data(large_buf, n);
  }
  
  printf("</filesystem-log>\n");
  return 0;
}

void version()
{
   printf("sandal, $Revision: 0.5 $\n");
}

void usage()
{
   version();
   printf("Copyright (C) Matterform Media, 2005");
   printf("\n");
   printf("usage: sandal [-h] [-G] [-U] [-P] [-r]\n");
   printf("\n");
   printf("options:\n");
   printf("\n");
   printf("   -h :   get help (this)\n");
   printf("   -P :   don't look up process names\n");
   printf("   -U :   don't look up user names\n");
   printf("   -G :   don't look up group names\n");
   printf("   -N :   don't look up anything at all (same as -P -U -G)\n");
   printf("   -r :   use REALbasic-format hex values (&hEA98) instead of C-format (0xEA98)\n");
}

/* supported options:
   -h:   display help information
   -G:   don't look up group name
   -U:   don't look up user name
   -P:   don't look up process name
   -N:   don't look up anything
   -r:   output RB-style hex values      
*/
void handle_commandline_options(int argc, char *argv[])
{
   // for getopt
   extern char *optarg;
   extern int optind, optopt;
   int errflag;
   char c;
   
   // setup default values -- look up everything
   lookup_owner_name = 1;
   lookup_group_name = 1;
   lookup_process_name = 1;
   errflag = 0;
   
   while ((c = getopt(argc, argv, "hGUPNrv")) != -1)
   {
      switch (c)
      {
         case 'h':
            usage();
            exit(0);
            break;
            
         case 'G':
            lookup_group_name = 0;
            break;
            
         case 'U':
            lookup_owner_name = 0;
            break;
         
         case 'P':
            lookup_process_name = 0;
            break;
            
         case 'N':
            lookup_group_name = 0;
            lookup_owner_name = 0;
            lookup_process_name = 0;
            break;
         
         case 'r':
            hex_output_prefix = "&amp;h";
            break;
         
         case 'v':
            version();
            exit(0);
            break;
            
         case '?':
            fprintf(stderr, "Unrecognized option: -%c\n", optopt);
            errflag++;
            break;
      }
   }
   
   if (errflag)
   {
      usage();
      exit(1);      
   }
}

/* event structure in mem:

event type: 4 bytes
event pid: sizeof(pid_t) (4 on darwin) bytes
args:
  argtype: 2 bytes
  arglen: 2 bytes
  argdata: arglen bytes
lastarg:
  argtype: 2 bytes = 0xb33f

*/

// parses the incoming event data and displays it in a friendly way
static void process_event_data(void *in_buf, int size) {
  int pos = 0;
  pid_t pid;
  uid_t uid;
  dev_t device;
  gid_t gid;
  int32_t mode;
  char buffer[0x100];
  u_int16_t argtype;
  u_int16_t arglen;
  
  char *close_tag;
  
  // printf("=> received %d bytes\n", size);

  do {
    // printf("# Event\n");
  
    // printf("  type           = ");
    switch (*((int32_t *) (in_buf + pos))) {
    case FSE_CREATE_FILE:
      // printf("CREATE FILE");
      printf("  <create-file>\n");
      close_tag = "</create-file>";
      break;
    case FSE_DELETE:
      // printf("DELETE");
      printf("  <delete>\n");
      close_tag = "</delete>";
      break;
    case FSE_STAT_CHANGED:
      // printf("STAT CHANGED");
      printf("  <stat-changed>\n");
      close_tag = "</stat-changed>";
      break;
    case FSE_RENAME:
      // printf("RENAME");
      printf("  <rename>\n");
      close_tag = "</rename>";
      break;
    case FSE_CONTENT_MODIFIED:
      // printf("CONTENT MODIFIED");
      printf("  <content-modified>\n");
      close_tag = "</content-modified>";
      break;
    case FSE_EXCHANGE:
      // printf("EXCHANGE");
      printf("  <exchange>\n");
      close_tag = "</exchange>";
      break;
    case FSE_FINDER_INFO_CHANGED:
      // printf("FINDER INFO CHANGED");
      printf("  <finder-info-changed>\n");
      close_tag = "</finder-info-changed>";
      break;
    case FSE_CREATE_DIR:
      // printf("CREATE DIR");
      printf("  <create-dir>\n");
      close_tag = "</create-dir>";
      break;
    case FSE_CHOWN:
      // printf("CHOWN");
      printf("  <chown>\n");
      close_tag = "</chown>";
      break;
    case FSE_INVALID: default:
      // printf("INVALID");
      printf("  <invalid/>\n");
      return; // <----------we return if invalid type (give up on this data)
      break;
    }
    // printf("\n");
    pos += 4;
  
    pid = *((pid_t *) (in_buf + pos));

    // handle the event number
    printf("    <eventNumber>%d</eventNumber>\n", global_event_counter++);
    
    // printf("  pid            = %d (%s)\n", pid, buffer);
    printf("    <process>\n");
    printf("      <id>%d</id>\n", pid);
    if (lookup_process_name)
    {
       get_process_name(pid, buffer, sizeof(buffer));
       if (isprintable(buffer))
           xmlprintf("      <name>%s</name>\n", buffer);       
    }
    printf("    </process>\n");
   
    pos += sizeof(pid_t);

    /* printf("  # Details\n"
	   "    # type       len  data\n"); */
  
    while(1) {
      argtype = *((u_int16_t *) (in_buf + pos));
      pos += 2;

      if (FSE_ARG_DONE == argtype) {
	      // printf("    DONE (0x%x)\n", argtype);
	      printf("    <done>%s%x</done>\n", hex_output_prefix, argtype);

	      break;
      }

      arglen = *((u_int16_t *) (in_buf + pos));
      pos += 2;

      switch(argtype) {
      case FSE_ARG_VNODE:
	      // printf("    VNODE%11d  path   = %s\n", arglen, (in_buf + pos));
	      xmlprintf("    <vnode>%s</vnode>\n", in_buf + pos);
	      break;
      case FSE_ARG_STRING:
	      // printf("    STRING%10d  string = %s\n", arglen, (in_buf + pos));
	      xmlprintf("    <string>%s</string>\n", in_buf + pos);
	      break;
      case FSE_ARG_PATH: // not in kernel
	      // printf("    PATH%12d  path   = %s\n", arglen, (in_buf + pos));
	      xmlprintf("    <path>%s</path>\n", in_buf + pos);
	      break;
      case FSE_ARG_INT32:
	      // printf("    INT32%11d  int32  = %d\n", arglen, *((int32_t *) (in_buf + pos)));
	      printf("    <int32>%d</int32>\n", *((int32_t *) (in_buf + pos)));
	      break;
      case FSE_ARG_INT64: // not supported in kernel yet
	      // printf("    INT64%11d  int64  = %lld\n", arglen, *((int64_t *) (in_buf + pos)));
	      printf("    <int64>%lld</int64>\n", *((int64_t *) (in_buf + pos)));
	      break;
      case FSE_ARG_RAW: // just raw bytes, can't display
	      // printf("    RAW%13d  raw\n", arglen);
	      printf("    <raw>%13d</raw>\n", arglen);
	      break;
      case FSE_ARG_INO:
	      // printf("    INODE%11d  ino    = %d\n", arglen, *((ino_t *) (in_buf + pos)));
	      printf("    <inode>%d</inode>\n", *((ino_t *) (in_buf + pos)));
	      break;
      case FSE_ARG_UID:
	      uid = *((uid_t *) (in_buf + pos));
	      // printf("    UID%13d  uid    = %d (%s)\n", arglen, uid, (getpwuid(uid))->pw_name);
	      printf("    <uid>\n");
	      printf("      <int>%d</int>\n", uid);
	      
	      if (lookup_owner_name)
	         xmlprintf("      <name>%s</name>\n", (getpwuid(uid))->pw_name);
	      
	      printf("    </uid>\n");
	      break; 
      case FSE_ARG_DEV:
	      device = *((dev_t *) (in_buf + pos));
	      // printf("    DEV%13d  dev    = 0x%x (major %d, minor %d)\n", arglen, device,
	      //       (device >> 24) & 0x0FFFFFF, device & 0x0FFFFFF);
	      printf("    <device>\n");
	      printf("      <value>%s%x</value>\n", hex_output_prefix, device);
	      printf("      <major>%d</major>\n", (device >> 24) & 0x0FFFFFF);
	      printf("      <minor>%d</minor>\n", device & 0x0FFFFFF);
	      printf("    </device>\n");
	      break;
      case FSE_ARG_MODE:
	      mode = *((int32_t *) (in_buf + pos));
	      get_mode_string(mode, buffer);
	      // printf("    MODE%12d  mode   = %s (0x%06x, vnode type %s)\n",
	      //       arglen, buffer, mode, get_vnode_type(mode));
	      printf("    <mode>\n");
	      printf("      <int>%s%06x</int>\n", hex_output_prefix, buffer);
	      printf("      <vnode-type>%s</vnode-type>\n", get_vnode_type(mode));
	      printf("      <str>%s</str>\n", buffer);
	      printf("    </mode>\n");
	      break;
      case FSE_ARG_GID:
	      gid = *((gid_t *) (in_buf + pos));
	      // printf("    GID%13d  gid    = %d (%s)\n", arglen, gid, (getgrgid(gid))->gr_name);
	      printf("     <gid>\n");
	      printf("       <int>%d</int>\n", gid);
	      
	      if (lookup_group_name)
	         xmlprintf("       <name>%s</name>\n", (getgrgid(gid))->gr_name);
	      
	      printf("     </gid>\n");
	      break; 
      default:
         // close the XML tag
         printf("  %s\n", close_tag);
	      return; // <----------we return if invalid type (give up on this data)
	      break;
      }
      pos += arglen;
    }

    printf("  %s\n", close_tag);

  } while (pos < size);

  return;
}

// dies with optional error message
static void die(int p) {
  if (p)
    perror(NULL);
  exit(1);
}

// returns a process name in out_buf
// mac os x specific
static void get_process_name(pid_t process_id, char *out_buf, int outsize) {
  int mib[4];
  size_t len;
  struct kinfo_proc kp;

  mib[0] = CTL_KERN;
  mib[1] = KERN_PROC;
  mib[2] = KERN_PROC_PID;
  mib[3] = process_id;

  len = sizeof(kp);
  if (sysctl(mib, 4, &kp, &len, NULL, 0) == -1) {
    strncpy(out_buf, "exited?", outsize);
  } else {
    strncpy(out_buf, kp.kp_proc.p_comm, outsize);
  }
}

// converts mode number to ls-style mode string
static void get_mode_string(int32_t mode, char *buf) {
  buf[10] = '\0';
  buf[9] = mode & 0x01 ? 'x' : '-';
  buf[8] = mode & 0x02 ? 'w' : '-';
  buf[7] = mode & 0x04 ? 'r' : '-';
  buf[6] = mode & 0x08 ? 'x' : '-';
  buf[5] = mode & 0x10 ? 'w' : '-';
  buf[4] = mode & 0x20 ? 'r' : '-';
  buf[3] = mode & 0x40 ? 'x' : '-';
  buf[2] = mode & 0x80 ? 'w' : '-';
  buf[1] = mode & 0x100 ? 'r' : '-';
 
  // ls style mode string
  if (S_ISFIFO(mode)) {
    buf[0] = 'p';
  } else if (S_ISCHR(mode)) {
    buf[0] = 'c';
  } else if (S_ISDIR(mode)) {
    buf[0] = 'd';
  } else if (S_ISBLK(mode)) {
    buf[0] = 'b';
  } else if (S_ISLNK(mode)) {
    buf[0] = 'l';
  } else if (S_ISSOCK(mode)) {
    buf[0] = 's';
  } else {
    buf[0] = '-';
  }
}

// just returns a string representation of a node type
static char *get_vnode_type(int32_t mode) {
  char *str_to_ret;

  if (S_ISFIFO(mode)) {
    str_to_ret = "VFIFO";
  } else if (S_ISCHR(mode)) {
    str_to_ret = "VCHR";
  } else if (S_ISDIR(mode)) {
    str_to_ret = "VDIR";
  } else if (S_ISBLK(mode)) {
    str_to_ret = "VBLK";
  } else if (S_ISLNK(mode)) {
    str_to_ret = "VLNK";
  } else if (S_ISSOCK(mode)) {
    str_to_ret = "VSOCK";
  } else {
    str_to_ret = "VREG";
  }

  return str_to_ret;
}

// is the string ascii?
int isprintable(char *str)
{
   int i, c;
   
   c = strlen(str);
   for (i = 0; i < c; i++)
      if (!isalnum(str[i]))
         return 0;
   
   return 1;
}
