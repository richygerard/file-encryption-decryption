/*
 * xCipher.h Header File 
 */

# include <stdio.h>
# include <string.h>
# include <unistd.h>
# include <stdlib.h>
# include <sys/types.h>
# include <sys/stat.h>
# include <fcntl.h>
# include <time.h>
# include <sys/mman.h>
# include <openssl/md5.h>
# include "struct.h"

/* Controls the Debugging Options */
//# define DEBUG 0

/* Sys_xCrypt System Call Number as Hardcoded in Kernel */
# define __sys_xcrypt 349

/* Message Digest Size of MD5 */
# define MD5_DIGEST 17

/* sys_xcrypt system call */
static inline long sys_xcrypt(int syscallno, void *arg) {
	return syscall(syscallno, arg);
}


/* Check_string checks the validity of the Passphrase */
char *check_string(char []);

/* Prints the Help */
void print_help();

/* Prints the MD5 value */
void print_md5();

