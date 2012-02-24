/*
 * Sys_xcrypt.h Header File
 */

# include <linux/module.h>
# include <linux/kernel.h>
# include <linux/slab.h>
# include <linux/fs.h>
# include <linux/uaccess.h>
# include <generated/autoconf.h>
# include <asm/unistd.h>
# include <linux/err.h>
# include <linux/scatterlist.h>
# include <linux/stat.h>
# include <linux/namei.h>
# include <linux/hash.h>
# include <linux/slab.h>
# include <linux/mm.h>
# include <linux/key-type.h>
# include <linux/ceph/decode.h>
# include <crypto/md5.h>
# include <crypto/aes.h>
# include <asm/scatterlist.h>
# include <keys/ceph-type.h>
# include "struct.h"

/* 
 * Controls the Debugging Options 
 * Using This will give too much of printk
 * statments that are useful for debugging
 */
/*
 * # define DEBUG 0
 */

/* Controls the Extra Credit */
/*
 * # define EXTRA_CREDIT 1
 */

/* Key Size for AES */
# define AES_KEY_SIZE 16

/* MD5 Digest Length */
# define MD5_DIGEST_LENGTH 16

/* Func() Prototype Declaration */
asmlinkage int func (void *kargs);

/* System Call prototype Declaration */
asmlinkage extern int (*xcrypt)(void *);

/* xcrypt_read() to read data */
int xcrypt_read(struct file *, void *, int);

/* xcrypt_write() to write data */
int xcrypt_write(struct file *, void *, int);

/* File Permissions and Access check */
int file_check(struct file *, int);
/* kencrypt encrypts data to dst */
static int kencrypt(const void *key, int key_len,
			    void *dst, size_t *dst_len,
			    const void *src, size_t src_len,
				int page, struct file *file_in);

/* kdecrypt decrypts data to dst */
static int kdecrypt(const void *key, int key_len,
			    void *dst, size_t *dst_len,
			    const void *src, size_t src_len,
				int page, struct file *file_in);

/* Hashing the Input key in the kernel */
static int crypto_hashing(unsigned char *, unsigned const char *, unsigned int);

/* Printing MD5 Value */
void print_md5(unsigned char *mess_dig);

/* Global variable to check if there is any Partial Write */
extern int partial_output;

/* File Sizes */
unsigned int infile_size;
unsigned int outfile_size;

/* Global Print Statement */
int global_print = 0;
