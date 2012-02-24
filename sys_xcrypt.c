/*
 * Author : Richy Gerard Devasahayam
 * Email : rdevasahayam@cs.stonybrook.edu
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of GNU General Public License Version
 * 2 as published by the the Free Software Foundation.
 *
 * Sys_xcrypt.c -  Kernel Module which performs the work of
 * Encrypting and Decryption Files when System Call Sys_xcrypt()
 * is called.
 *
 * Program for Sys_Xcrypt *
 */

#include "sys_xcrypt.h"


/*
 * Func() processes the user arguments from User space and
 * copies it into Kernal space. The xCrypt_read & xCrypt_write
 * perform the read and write operations on the input and output
 * files. Kencrypt() & Decrypt() encrypts and decrypts the file
 * using AES CBC Mode.
 */
asmlinkage int func(void *uargs)
{
	int i = 0, err = 0;
	int page = 0; 
	int flag, key_length = 0, rename = 0;
	int partial_output = 0, xcrypt_success = 1;
	int bytes_read = 0, bytes_written = 0, bytes_left = 0, temp_bytes = 0;
	int t_bytes_read = 0, t_bytes_written = 0;
	unsigned char key_buffer[SIZE];
	char string_temp[SIZE_] = "";
	ssize_t length = 0;
	ssize_t *dstlen;
	void *buffer_in = NULL, *buffer_out = NULL;
	struct file *file_in = NULL, *file_out = NULL, *file_temp = NULL;
	struct dentry *temp = NULL, *out = NULL;

	/* Malloc'ing kargs in kernel space */
	karguments *kargs = kmalloc(sizeof(karguments), GFP_KERNEL);

	/* Destination length pointer in the input/output buffers */
	dstlen = kmalloc(sizeof(ssize_t), GFP_KERNEL);

	/* Checking the validity of Kernel space argument buffer */
	if ((!kargs)) {
		printk(KERN_INFO "Malloc Failed.\n");
		err =  -ENOMEM;
		goto exit;
	}

	/* Verifying the read access of Kernal space arguments */
	if(!access_ok(VERIFY_READ, uargs, sizeof(karguments))) {
		printk(KERN_INFO "Access Not Granted.\n");
		err =  -EFAULT;
		goto exit;
	}

	/* Copying the User space arguments to Kernal space arguments */
	if(copy_from_user(kargs, (karguments *) uargs, sizeof(karguments))!=0) {
		printk(KERN_INFO "Copy from User Failed.\n");
		err = -EFAULT;	
		goto exit;
	}

	/* Checking the Validity of Kernel space arguments */
	if((kargs->infile == NULL) || (kargs->outfile == NULL) || (kargs->key_buffer \
			== NULL) || (kargs->key_length == 0)) {
		printk(KERN_INFO "Invalid Arguments.\n");
		err = -EINVAL;
		goto exit;
	}

	/* Checking the missing Kernal space arguments */
	if((!kargs->infile) || (!kargs->outfile) || (!kargs->key_buffer) || \
			((kargs->flag != 0) && (kargs->flag !=1))) {
		printk(KERN_INFO "Missing Arguments.\n");
		err = -EINVAL;
		goto exit;
	}

	/* Copying the Arguments */
	key_length = kargs->key_length;
	
	/* Hashing Inside the Kernel */
	err = crypto_hashing(key_buffer, kargs->key_buffer, (unsigned int)\
							 key_length);	
	if(err <0) {
		printk(KERN_INFO "Error in Crypto Hash.\n");
		goto exit;
	}

	flag = kargs->flag;

	/* Checking the validity of the Key Buffer by its length */
	if(strlen(kargs->key_buffer) != key_length) {
		printk(KERN_INFO "Length of Key Buffer & Key Length differ.\n");
		err = -EINVAL;
		goto exit;
	}

	printk(KERN_INFO "---------------------------");
	printk(KERN_INFO "     xCrypt System Call    ");
	printk(KERN_INFO "---------------------------");
	printk(KERN_INFO "Infile's Name : %s", kargs->infile);
	printk(KERN_INFO "Outfile's Name : %s", kargs->outfile);

	/* Checking for Symlinks */
/*	err = kern_path((char *)kargs->infile, LOOKUP_FOLLOW, &buf);

	if(err < 0) {
		printk(KERN_INFO "Symlink in Input File.\n");
		goto exit;
	}
	err = kern_path((char *)kargs->outfile, LOOKUP_FOLLOW, &buf);

	if(err < 0) {
		printk(KERN_INFO "Symlink in Output File.\n");
		goto exit;
	}
*/
	/* 
	 * Opening Input file (file_in) & Output file (file_out) with
	 * required permissions of the Input file
	 */
	file_in = filp_open (kargs->infile, O_RDONLY, 0);
	err = file_check(file_in, 1);
	
	if (err < 0) {
		printk(KERN_INFO "Error in Input File.\n");
		goto exit;
	}

	/* Creating a temporary file name */	
	strcat(string_temp, kargs->infile);
	strcat(string_temp, ".tmp");	
	printk(KERN_INFO "Temporary File's Name : %s", string_temp);

        file_temp = filp_open (string_temp, O_WRONLY|O_CREAT|O_TRUNC,file_in-> \
						f_dentry->d_inode->i_mode);
	err = file_check(file_temp, 2);

	if (err < 0) {
		printk(KERN_INFO "Error in Temp File.\n");
		goto cleanup_file;
	}

	if (file_in->f_dentry->d_inode->i_ino == file_temp->f_dentry \
							->d_inode->i_ino) {
		printk(KERN_INFO "Input and Temp file match the same inode.\n");
		err = -EBADF;
		goto cleanup_file;
	}
	
	/* Finding the size of the Input file (infile) */
	infile_size = file_in->f_dentry->d_inode->i_size;

	/* Initializing the temp */
	temp = file_temp->f_dentry;
	file_temp->f_pos = 0;

	/* Buffer_in : Input Buffer for Reading Data
	 * Buffer_out : Output Buffer for Writing Data
	 */
	buffer_in = kmalloc(PAGE_SIZE, GFP_KERNEL);
	buffer_out = kmalloc(PAGE_SIZE, GFP_KERNEL);

	/* Error conditions for Malloc failing for buffer_in || buffer_out */
	if ((!buffer_in) || (!buffer_out)) {
		err =  -ENOMEM;
		goto cleanup_file;
	}

	/* For Encryption, we write the Preamble on the Temp file */
	if (flag == 1){	
		printk(KERN_INFO "Writing Preamble onto the Temp File.\n");
		if ((bytes_written = xcrypt_write(file_temp, key_buffer, 16)) \
									 <1) {
			printk(KERN_INFO "Preamble Append Error.\n");
			partial_output = 1;
			err = -EIO;
			goto cleanup_file;
		}
        	file_temp->f_pos = 16;
		t_bytes_written = 16;
	}

	/* For Decryption, file pointer is moved to read data after preamble */
	if (flag == 0) {
    		memset(buffer_in,'\0', PAGE_SIZE);
		bytes_read = xcrypt_read(file_in, buffer_in, 16);
		for (i = 0; i < SIZE; i++) {
			if (((unsigned char *) buffer_in) [i] != key_buffer[i]) {
				printk(KERN_INFO "Decryption Key is Invalid.\n");
				err = -EINVAL;
				goto cleanup_file;
			}
		}	
		t_bytes_read = 16;
		file_in->f_pos = 16; 
	}

	if (flag == 1)
		bytes_left = infile_size;
	else
		bytes_left = infile_size - 16;
	page = 0;

	/* Loop runs until all the data are extracted from the Infile */	
	while (bytes_left > 0) {
		length = 0;
		bytes_read = 0;
		bytes_written = 0;
		temp_bytes = 0;

		/* 
		 * Memsetting the Buffer_in & Buffer_out which also helps
		 * as a one way of padding the data to the Encryption/
		 * Decryption.
		 */
    		memset(buffer_in, '\0', PAGE_SIZE);
    		memset(buffer_out, '\0', PAGE_SIZE);

		/*
		 * Flag for Encryption
		 * If Encryption, then 16 bytes is reserved for Preamble
		 */
		if (flag == 1) {
			if (bytes_left > (PAGE_SIZE - 16)) {
				temp_bytes = PAGE_SIZE - 16;
				bytes_left = bytes_left - temp_bytes ;
				global_print = 0;
			}
			else {
				temp_bytes = bytes_left;
				bytes_left = 0;
				global_print = 1;
			}
		}

		/*
		 * Flag for Decryption
		 * If Decryption, then allot PAGE_SIZE for 
		 * Input Buffer and process it 
		 */
		if (flag == 0) {
			if (bytes_left > (PAGE_SIZE)) {
				temp_bytes = PAGE_SIZE;
				bytes_left = bytes_left - temp_bytes ;
				global_print = 0;
			}
			else {
				temp_bytes = bytes_left;
				bytes_left = 0;
				global_print = 1;
			}
		}

		/* Reading 'temp_bytes' of data from file_in */
		if ((bytes_read=xcrypt_read(file_in, buffer_in, temp_bytes)) \
								<1) {
			printk(KERN_INFO "Bytes read is <1.\n");
			err = -EIO;
			goto cleanup_file;
		}

		/* 
		 * File Encryption involves Reading the input file,
		 * Encrypting it and then Writing the data to the 
		 * Output file
		 */
		if (temp_bytes != bytes_read) {
			printk(KERN_INFO "Error in reading the Temporary \
							 bytes.\n");
		}
	
		/* Encrypt File with 'buffer_in' data to 'buffer_out' data */
		if (flag == 1) {
			err = kencrypt(key_buffer, key_length, buffer_out, \
			dstlen, buffer_in, temp_bytes, page, file_temp);
			if (err < 0) {
				partial_output = 1;
				printk(KERN_INFO "Encryption Failed.\n");
				goto cleanup_file;
			}
		}
		
		/* Decrypt File with 'buffer_in' data to 'buffer_out' data */
		else if (flag == 0) {
			err = kdecrypt(key_buffer, key_length, buffer_out, \
			dstlen, buffer_in, temp_bytes, page, file_in);
			if (err < 0) {
				printk(KERN_INFO "Decryption Failed.\n");
				partial_output = 1;
				goto cleanup_file;
			}
		}
	
		length = *dstlen;

		#ifdef DEBUG
			printk ( KERN_INFO "Length of Encrypted/Decrypted \
					 BLOCK is %Zu\n",length);
		#endif

		/* Write the 'len' bytes of 'Buffer_out' data to 'File_out' */
		if ((bytes_written = xcrypt_write(file_temp, buffer_out,\
						 (int) length)) <1) {
			printk(KERN_INFO "Bytes written to Outfile is <1.\n");
			partial_output = 1;
			err = -EIO;
			goto cleanup_file;
		}

		page++;
		t_bytes_read = t_bytes_read + bytes_read;
		t_bytes_written = t_bytes_written + bytes_written;

		/* Partially written files are Unlinked from the directory */
		if (partial_output == 1) {
			printk(KERN_INFO "Out file is partially written.\n");
			goto cleanup_file;
		}
	}

	printk(KERN_INFO "No of bytes read from Infile : %d\n", t_bytes_read);
	printk(KERN_INFO "No of bytes written to Outfile : %d\n", \
							 t_bytes_written);

	/* Creating Output File */
        file_out = filp_open (kargs->outfile, O_WRONLY|O_CREAT|O_TRUNC,\
				file_in->f_dentry->d_inode->i_mode);

	err = file_check(file_out, 2);

	/* Permission of Files & Sizes */
	printk(KERN_INFO "Infile's Permission : %04o", file_in->f_dentry-> \
						d_inode->i_mode & 07777); 
	printk(KERN_INFO "Outfile's Permission : %04o", file_out->f_dentry-> \
						d_inode->i_mode & 07777); 
	printk(KERN_INFO "Infile's Size : %d ", (int)infile_size);

	if (err < 0) {
		printk(KERN_INFO "Error in Output File.\n");
		xcrypt_success = 0;
		goto cleanup_file;
	}

	if (file_in->f_dentry->d_inode->i_ino == file_out->f_dentry-> \
							d_inode->i_ino) {
		printk(KERN_INFO "Input & Output files matc  same inode.\n");
		err = -EBADF;
		xcrypt_success = 0;
		goto cleanup_file;
	}

	if ((file_in->f_dentry->d_inode->i_ino == file_out->f_dentry->d_inode \
	->i_ino) && (file_in->f_dentry->d_inode->i_sb == file_out->f_dentry-> \
							d_inode->i_sb)) {
		printk(KERN_INFO "Infile/Outfile have Symlinks/Same Inodes.\n");
		err = -EBADF;
		xcrypt_success = 0;
		goto cleanup_file;
	}
	/* Initializing the temp */
	out = file_out->f_dentry;

	/* Renaming the Temporary file to Output file */
	err = vfs_rename(temp->d_parent->d_inode, temp, 
				out->d_parent->d_inode, out);
	
	if (err < 0) {
		printk(KERN_INFO "Error in Renaming Temp File.\n");
		xcrypt_success = 0;
		goto cleanup_file;
	}
	rename = 1;
	printk(KERN_INFO "Outfile written Successfully. Cheers. \n");

	cleanup_file:
		
		if (file_out!= NULL)
			if (!IS_ERR(file_out))
				filp_close(file_out, NULL);

		if (file_out!= NULL)
			if (!IS_ERR(file_out))
				filp_close(file_out, NULL);

		if (file_temp!= NULL)
			if (!IS_ERR(file_temp))
				filp_close(file_temp, NULL);

		if (xcrypt_success == 0)
			if (out) {
				vfs_unlink(temp->d_parent->d_inode, temp);
				printk(KERN_INFO "Removing Output File");
			}
		if (rename == 1)
			if (temp) {
				vfs_unlink(out->d_parent->d_inode, out);
				printk(KERN_INFO "Removing Temp File");
			}
		if (rename == 0)
			if (temp) {
				vfs_unlink(temp->d_parent->d_inode, temp);
				printk(KERN_INFO "Removing Temp File");	
			}			
	exit:
		if (dstlen != NULL)
			kfree(dstlen);

		if (kargs != NULL)
			kfree(kargs);

		if (buffer_in != NULL)
			kfree(buffer_in);

		if (buffer_out != NULL)
			kfree(buffer_out);

		printk(KERN_INFO "Exiting %s with err = %d.", __func__, err);
		printk(KERN_INFO "---------------------------");

		return err;
}

/* Checking the Files for Read/Write Accesses */
int file_check(struct file *f, int flag)
{
	int err = 0;
	/* Checking if file pointer exists */
	if (!f) {
		printk(KERN_INFO "File does not Exist/Bad File.\n");
		err = -EBADF;
		goto exit;
	}

	/* Checking Error in File Pointer f */
	if (IS_ERR(f)) {
                printk(KERN_INFO "File error : %d\n", (int) PTR_ERR(f));
		err = PTR_ERR(f);
		goto exit;
	}

	/* Checking the regularity of input and output files */
        if ((!S_ISREG(f->f_dentry->d_inode->i_mode))) {
                printk(KERN_INFO "Input Or Output File is not regular.\n");
		err = -EIO;
                goto exit; 
        }

	if (flag == 1) {
		/* Checking the file read permissions of Input file */
		if (!(f->f_mode & FMODE_READ)) {
			printk(KERN_INFO "Infile not accessible to be read.\n");
			err = -EIO;
			goto exit;
		}

		/* Checking if Input File can be read */
	        if (!f->f_op->read) {
	                printk(KERN_INFO "File System does not allow reads.\n");
	                err = -EACCES; 
			goto exit;
	        }

		#ifdef DEBUG
       			printk(KERN_INFO "File read check Successful.\n");
  		#endif
	
	}

	if (flag == 2) {

		/* Checking the file read permissions of Output file */
		if (!(f->f_mode & FMODE_WRITE)) {
			printk(KERN_INFO "Output File not accessible to be \
							 written.\n");
			err = -EIO;
			goto exit;
		}

		/* Checking if Output File can be written*/
	        if (!f->f_op->write) {
        	        printk(KERN_INFO "File System does not allow writes.\n");
             		err = -EACCES; 
	                goto exit;
	        }

		#ifdef DEBUG
			printk(KERN_INFO "File write check Successful.\n");
		#endif

	}
	return 0;
	exit:
		return err;
}


/*
 * xCrypt_read reads the data from the input file 
 * and copies it to buffer_in : Input Buffer
 */
int xcrypt_read(struct file *file_in, void *buffer_in, int len)
{
    	int bytes = 0;
	int err = 0;
    	mm_segment_t oldfs;

	/* Checking input file for Access errors */
	if (!file_in) {
		printk(KERN_INFO "Input File Access Error.\n");
		err = -EACCES;
		goto exit;
	}

	/*	
	 * Changing the Data Segment to Kernel Data Segment
	 * and reading the contents of the file. After reading,
	 * the old data segment is replaced.
	 */	
    	oldfs = get_fs();
    	set_fs(KERNEL_DS);
    	bytes = file_in->f_op->read(file_in, buffer_in, len, &file_in->f_pos);
    	set_fs(oldfs);

	/* Display Bad File Error when read bytes < 0 || 0 */
	if ((bytes == 0) || (bytes < 0)) {
		printk(KERN_INFO "Input File read not successful.\n");
		err = -EBADF;
		goto exit;
	}
	
	if(global_print)
		printk(KERN_INFO "Input File read successful.\n");
    	return bytes;
	
	exit :
		printk(KERN_INFO "Exiting %s with error %d", __func__, err);
		return err;
}

/*
 * xCrypt_write writes the data to the output file 
 * by copying from the buffer_out : Output Buffer
 */
int xcrypt_write(struct file *file_out, void *buffer_out, int len)
{
    	int bytes = 0;
	int err = 0;
	mm_segment_t oldfs; 

	/* Checking the Output file for Access errors */
	if (!file_out) {
		printk(KERN_INFO "Temp File Access Error.\n");
		err = -EACCES;
		goto exit;
	}

	/*	
	 * Changing the Data Segment to Kernel Data Segment
	 * and reading the contents of the file. After reading,
	 * the old data segment is replaced.
	 */	
    	oldfs = get_fs();
    	set_fs(KERNEL_DS);
    	bytes = file_out->f_op->write(file_out, buffer_out, len, \
						 &file_out->f_pos);
    	set_fs(oldfs);

	/* Display Bad File Error when write bytes <0 || 0 */
	if ((bytes == 0) || (bytes < 0)) {
		printk(KERN_INFO "Temp File write unsuccessful.\n");
		err = -EBADF;
		goto exit;
	}

	if (global_print)
        	printk(KERN_INFO "Temp File write successful.\n");
    	return bytes;

	exit : 
		printk(KERN_INFO "Exiting %s with error %d", __func__, err);
		return err;
}


static struct crypto_blkcipher *ceph_crypto_alloc_cipher(void)
{
	return crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
}

#ifdef EXTRA_CREDIT
#else
	static const u8 *aes_iv = (u8 *)CEPH_AES_IV;
#endif

/*
 * Kencrypt() uses Input Key, Input Key's Length,
 * Destination Buffer, Destination Buffer Length,
 * Source Buffer, Source Buffer Length
 * to encrypt the file.
 * Kencrypt() is derived from ceph_aes_encrypt()
 */
static int kencrypt(const void *key, int key_len,
			    void *dst, size_t *dst_len,
			    const void *src, size_t src_len,
			int page, struct file *file_out)
{
	int ret;
	int ivsize;
	char pad[48];
	size_t zero_padding = (0x10 - (src_len & 0x0f));
	struct scatterlist sg_in[2], sg_out[1];
	struct crypto_blkcipher *tfm = ceph_crypto_alloc_cipher();
	struct blkcipher_desc desc = { .tfm = tfm, .flags = 0 };
	void *iv;

	#ifdef EXTRA_CREDIT
		u32 ino = file_out->f_dentry->d_inode->i_ino;
		long l_page = (long) page;
		long l_ino = (long) ino;
		void *augment_iv;
	#endif

	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	memset(pad, zero_padding, zero_padding);

	*dst_len = src_len + zero_padding;

	/* Setting the Key for Block cipher */
	crypto_blkcipher_setkey((void *)tfm, key, key_len);
	sg_init_table(sg_in, 2);
	sg_set_buf(&sg_in[0], src, src_len);
	sg_set_buf(&sg_in[1], pad, zero_padding);
	sg_init_table(sg_out, 1);
	sg_set_buf(sg_out, dst,*dst_len);

	/* Customizing Initialization Vector for Extra Credit A */ 
	iv = crypto_blkcipher_crt(tfm)->iv;
	ivsize = crypto_blkcipher_ivsize(tfm);

	/* 
	 * Initialization Vector being Customized with the Page Number
	 * and Inode value of the input file.
	 */
	#ifdef EXTRA_CREDIT

		#ifdef DEBUG
			printk(KERN_INFO "Iv Size is %d", ivsize);
			printk(KERN_INFO "Page Value is %d", page);
			printk(KERN_INFO "Inode Value is %d", (int)ino);
		#endif
	
		augment_iv = (void *) kmalloc(16, GFP_KERNEL);
		memset(augment_iv, '\0', 16);
		memcpy((void *) augment_iv, (void *) &l_page, 8);
		memcpy((void *) augment_iv+8, (void *) &l_ino, 8);
	
		/* Memcopying AES_IV and IV */
		memcpy(iv, augment_iv, 16);
	#else
		memcpy(iv, aes_iv, ivsize);
	#endif

	/*
	print_hex_dump(KERN_ERR, "enc key: ", DUMP_PREFIX_NONE, 16, 1,
		       key, key_len, 1);
	print_hex_dump(KERN_ERR, "enc src: ", DUMP_PREFIX_NONE, 16, 1,
			src, src_len, 1);
	print_hex_dump(KERN_ERR, "enc pad: ", DUMP_PREFIX_NONE, 16, 1,
			pad, zero_padding, 1);
	*/

	/* Encrypting the Block Cipher */
	ret = crypto_blkcipher_encrypt(&desc, sg_out, sg_in,
                                     src_len + zero_padding);
	crypto_free_blkcipher(tfm);
	
	if (global_print)
		printk(KERN_INFO "---------------------------\n");

	if (ret < 0)
		pr_err("AES ENCRYPTION FAILED : %d\n", ret);

	if (global_print) {
		printk(KERN_INFO "AES ENCRYPTION SUCCESSFUL\n");
		printk(KERN_INFO "---------------------------\n");
	}

	 /*
	print_hex_dump(KERN_ERR, "enc out: ", DUMP_PREFIX_NONE, 16, 1,
                   dst, *dst_len, 1);
	*/
	#ifdef EXTRA_CREDIT
		kfree(augment_iv);
	#endif
	return 0;
}

/*
 * Kdecrypt() uses Input Key, Input Key's Length,
 * Destination Buffer, Destination Buffer Length,
 * Source Buffer, Source Buffer Length
 * to decrypt the file.
 * Kdecrypt() is derived from ceph_aes_decrypt()
 */
static int kdecrypt(const void *key, int key_len,
			   void *dst, size_t *dst_len,
			const void *src, size_t src_len,
			int page, struct file *file_in)
{
	int ivsize;
	int ret;
	int last_byte;
	char pad[48];
	struct scatterlist sg_in[1], sg_out[2];
	struct crypto_blkcipher *tfm = ceph_crypto_alloc_cipher();
	struct blkcipher_desc desc = { .tfm = tfm };
	void *iv;

	#ifdef EXTRA_CREDIT
		void *augment_iv;
		u32 ino = file_in->f_dentry->d_inode->i_ino;
		long l_ino = (long) ino;
		long l_page = (long) page;
	#endif

	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	/* Setting the key for Block cipher */
	crypto_blkcipher_setkey((void *)tfm, key, key_len);
	sg_init_table(sg_in, 1);
	sg_init_table(sg_out, 2);
	sg_set_buf(sg_in, src, src_len);
	sg_set_buf(&sg_out[0], dst, *dst_len);
	sg_set_buf(&sg_out[1], pad, sizeof(pad));

	/* 
	 * Initialization Vector being Customized with the Page Number
	 * and Inode value of the input file.
	 */
	iv = crypto_blkcipher_crt(tfm)->iv;
	ivsize = crypto_blkcipher_ivsize(tfm);

	/* Copying the initializer into IV */
	#ifdef EXTRA_CREDIT
		#ifdef DEBUG
			printk(KERN_INFO "Iv Size is %d", ivsize);
			printk(KERN_INFO "Page Value is %d", page);
			printk(KERN_INFO "Inode Value is %d", (int)ino);
		#endif
		augment_iv = kmalloc(16, GFP_KERNEL);
		memset(augment_iv, '\0', 16);
		memcpy((void *) augment_iv,(void *)  &l_page, 8);
		memcpy((void *) augment_iv+8,(void *)  &l_ino, 8);
		memcpy(iv, augment_iv, 16);
	#else
		memcpy(iv, aes_iv, ivsize);
	#endif

	/*
	print_hex_dump(KERN_ERR, "dec key: ", DUMP_PREFIX_NONE, 16, 1,
		       key, key_len, 1);
	print_hex_dump(KERN_ERR, "dec  in: ", DUMP_PREFIX_NONE, 16, 1,
		       src, src_len, 1);
	*/

	/* Crypto Block Cipher Decryption */
	ret = crypto_blkcipher_decrypt(&desc, sg_out, sg_in, src_len);

	crypto_free_blkcipher(tfm);

	if (global_print)
		printk(KERN_INFO "---------------------------\n");
	if (ret < 0) {
		pr_err("AES DECRYPTION FAILED : %d\n", ret);
		return ret;
	}

	if (src_len <= *dst_len)
		last_byte = ((char *)dst)[src_len - 1];
	else
		last_byte = pad[src_len - *dst_len - 1];

	if (last_byte <= 16 && src_len >= last_byte) {

		*dst_len = src_len - last_byte;
	} 
	else {
		pr_err("INVALID KEY!!\n");
                 return -EPERM;  /* bad padding */
         }

         /*
         print_hex_dump(KERN_ERR, "dec out: ", DUMP_PREFIX_NONE, 16, 1,
                        dst, *dst_len, 1);
         */

	if (global_print) {	
		printk(KERN_INFO "AES DECRYPTION SUCCESSFUL\n");
		printk(KERN_INFO "---------------------------\n");
	}

	#ifdef EXTRA_CREDIT
		kfree(augment_iv);
	#endif
        return 0;
 }

/*
 * print_md5() prints the MD5 Digest of the Input MD5 Hash
 */
void print_md5(unsigned char *mess_dig) {
	int i;
	for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
		printk(KERN_INFO "%02x", mess_dig[i]);
	}
	printk(KERN_INFO "\n");
}

/* Encrypting the Passphrase again */

static int crypto_hashing(unsigned char *buffer_out, unsigned const \
				 char *buffer_in, unsigned int len)
{
	int error;
	struct scatterlist sg[2];
	struct crypto_hash *tfm = crypto_alloc_hash("md5", 0, \
				 CRYPTO_ALG_TYPE_HASH);
	struct hash_desc desc = {.tfm = tfm};

	if (tfm == NULL) {
		printk(KERN_INFO "Error .\n");
		error = -EFAULT;
		goto exit;
	}

	error = crypto_hash_init(&desc);
	if (error != 0){
		printk(KERN_INFO "Error .\n");
		error = -EFAULT;
		goto exit;
	}	

	/* Using Buffer_in as User Space Hash */    
	sg_init_table(sg, ARRAY_SIZE(sg));
	sg_set_buf(&sg[0], buffer_in, len);

	/* Buffer_out as Kernel Space Hash - Double Hashing :) */
	error = crypto_hash_digest(&desc, sg, 1, buffer_out);

	if (error != 0){
		printk(KERN_INFO "Error .\n");
		error = -EFAULT;
		goto exit;
	}
	return 0;

	exit:
		return error;
}

/* Initializer : Module Sys_Xcrypt */
int init_module(void)
{
	xcrypt = &func;
	printk(KERN_INFO "xCrypt Module is loaded into Kernel successfully.\n");
	return 0;
}

/* Cleanup : Module Sys_Xcrypt */
void cleanup_module(void)
{
	xcrypt = NULL;
	printk(KERN_INFO "xCrypt Module unloaded from Kernel successfully.\n");
}


MODULE_AUTHOR("Richy Gerard : rdevasahayam@cs.stonybrook.edu");
MODULE_DESCRIPTION("xCrypt System Call to Encrypt & Decrypt Files.");
MODULE_LICENSE("Dual BSD/GPL");
