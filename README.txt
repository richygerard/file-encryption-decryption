----------------------------------------------------------------
LINUX LOADABLE KERNEL MODULE FOR FILE ENCRYPTION AND DECRYPTION
----------------------------------------------------------------

-------------
INTRODUCTION
-------------

	* Sys_xcrypt() system call has been implemented in Linux 3.2.2 Kernel of CentOS Operating System for encryption and decryption of files. 

	* A new system call has been implemented in Linux 3.2.2 Kernel which reads the input files and encrypts/decrypts the data and produces output file as per the given passphrase.


--------------------
SYSTEM REQUIREMENTS
--------------------

	* The system call sys_xcrypt() is implemented in CentOS v 3.2.2. Gcc version is 4.1.2 which compiles the xCipher user level code as well as the kernel module code.
	
	* For MD5 Hashing, xCipher will require OpenSSL libraries. To work with that, we need to install openssl-devel and openssl libraries.
	
	* An Input file is required for encrypting / decrypting the data.
	
	
-------------
SOURCE CODE
-------------

	The following files are present in the folder SYS_XCRYPT
	
	* SYS_XCRYPT.C : Kernel Module Program which implements the system call sys_xcrypt(). 
	
	* XCIPHER.C : User Level Program which acts a driver program for the system call and calls sys_xcrypt() system call for testing purposes.
	
	* SYS_XCRYPT.H : Kernel Module Program header file.
	
	* XCIPHER.H : User Level Program header file.
	
	* STRUCT.H : Header file common to both User and Kernel Level Programs which implements the structure for passing arguments from User space to Kernal space.
	
	* MAKEFILE : Makefile is used to 'make' the program and convert it into executables : "xcipher" [USER] & "sys_xcrypt.ko" [KERNEL].
	
	* README : Ofcourse, This is the Readme file :)
	
	
--------------------
PROJECT COMPLETION
--------------------

	* Basic Part of file Encryption and Decryption has been completed.
	
	
------------------
FUNCTIONAL DESIGN
------------------

	* KERNEL TWEAK 
			In Linux Kernel 3.2.2, A new system call has been added to the system call table system_call_table[].  In this program, I use a statically linked module to execute my system call. I added an entry in the system call table for sys_xcrypt(), modified the Linux Kernel Source and compiled the kernel. 
			
	* LINUX TWEAK
			When the system call is invoked from the user level driver program, the functions defined for sys_xcrypt() will play the role. The System call sys_xcrypt() cannot be called like the traditional function calling, instead we call the program by syscall() providing the system call number and the arguments.
	
	* INPUT AND OUTPUT FILE TWEAK
			When the executable provides a proper encrypted / decrypted data on the output file on successul completion, the file mode is set that only the user can read and write the file.
			
	* ENCRYPTION & DECRYPTION TWEAK
			From the Linux resource at lxr.fsl.cs.stonybrook.edu, I found the kernel source code in /net/ceph/crypto.c  : ceph_aes_encrypt() and ceph_aes_decrypt() which could process the input key, read the input data and produce the corresponding encrypted/decrypted data. As a Kernel Programmer and Open Source lover, we need to reuse the code. Whats the point in not reusing the code when I'm a open source lover? So, I used the two functions ces_aes_encrypt() - kencrypt() and ces_aes_decrypt() - kdecrypt() for encryption and decryption of AES Ciphers.
			
	* KEY 
			From the User Driver Program, a 16 byte digest of hashed passphrase is sent to the kernel space using MD5. In this way, the user's passphrase is encrypted and passed as an argument for the system call. In order to make the password more secure, we do another hashing inside the Kernel. In the same way when we decrypt, we get the encryption key first and then check if its a valid or an invalid key.
			

---------------
KERNEL DESIGN
---------------

	Things edited in Kernel :
	
		All entries which are listed below can be found in the last few lines in each of the file in the directory as specified.
		
		* Added System Call sys_xcrypt() statically into Kernel - As adding a system call into the Kernel would be more tedious than a statically linked system call, I prefer a statically linked system call as a loadable kernel module. 
		
		* Added an entry for sys_xcrypt() as a long type in 
		
			/usr/src/hw1-rdevasahayam/arch/x86/kernel/syscall_table_32.S :
				
				. long sys_xcrypt
				
		* Added an entry for defining the number of system call sys_xcrypt() in
		
			/usr/src/hw1-rdevasahayam/arch/x86/include/asm/unistd_32.h
			
				#define __NR_xcrypt     349 /* Defining the system call sys_xcrypt() Number */

				#define NR_syscalls 	350 /* Increasing the total number of system calls  */

				I define the system call number for sys_xcrypt() as 349 and use this value as my system call number for calling it from the user level program. Also, I increase the number of system calls by 1 ie. 349 + 1 = 350, total number of system calls is 350. 
				
		* Added an entry for the System call sys_xcrypt() function prototype in 
		
				/usr/src/hw1-rdevasahayam/include/linux/syscalls.h
				
					asmlinkage long sys_xcrypt(void __user *kargs);
					
		* Added an entry for the System Call sys_xcrypt() function to create a function pointer xcrypt() in
		
				/usr/src/hw1-rdevasahayam/fs/open.c 
					
					asmlinkage int (*xcrypt) (void*) = NULL;

					EXPORT_SYMBOL(xcrypt);

					asmlinkage long sys_xcrypt(void __user *kargs)
					{
						if(xcrypt!=NULL)
							return xcrypt(kargs);
						else
							return -ENOSYS;
					}

					
	These are the kernel tweaks that are done in my kernel. To explain about the lines of code above, when a system call sys_xcrypt() is invoked by its system call number in user level driver program, the function pointer *xcrypt() is being checked as NULL or not. If it is null, the system call error is thrown or else, xcrypt() is called passing the user arguments to the kernel space. 
	
	Now, after making the changes, 'make' and recompile the kernel. After installing ther kernel, compile the kernel module and user program as executable. The system call executes when the module 'sys_xcrypt.ko' is inserted into the kernel by 'insmod sys_xcrypt.ko'. Find the inserted module in lsmod and check the count. To remove the module from the kernel, use 'rmmod sys_xcrypt.ko'.
	
---------------------
KERNEL MODULE DESIGN
---------------------

	*	In the Kernel Module, there are various checks on boundary conditions which are required since we are in kernel mode and we have exclusive access for everything. We need to build our module to be too robust and prone to error conditions.
	
		CHECK FILES :
			a. Validity of Input and Output Files
			
			b. Check if files can be read/writen
			
			c. Check if input file has read permissions to be accessed
			
			d. Check if input file can be read (a file)
			
			e. Checking if input and output files match to the same inode number
			
		
		INPUT/OUTPUT FILE :
			a. Output file is created with the flags :	O_WRONLY|O_CREAT|O_TRUNC - where WRONLY - is for write, CREAT is for creation, TRUNC is for truncating the file if output file exists. However, the CREAT option will make make the file to be read and written by the user.
			
			b. The Output file will have user id and group id set by filp_open() as per the running process automatically. I checked it in man pages of filp_open().
			
			c. Output File on Partial write will be deleted on incomplete/unsuccessful encryption/decryption of files.
			
			d. Each time of reading/writing from files will be checked upon the successful number of bytes read or written. Else an error is displayed.

	* BUFFER_IN & BUFFER_OUT :
		
			a. Buffer IN and Buffer OUT are malloc'ed in PAGE_SIZE for the input /output buffers from reading data from file, encrypting or decrypting, and then writing the data to the output file.
			
			b. Any error in reading/writing data from Buffer IN or Buffer OUT will set the partial_write option which will unlink the partially written file from the file system.
			
	* ENCRYPTION AND DECRYPTION :
	
		Check for the Flag if encryption or decryption and invoke the corresponding, kencrypt() or kdecrypt() after successful reading of data from the input file.
		
		If encryption, the number of bytes that is read from input file will be a maximum of PAGE_SIZE - 16. Else for decryption, the maximum size will be PAGE_SIZE. An initialization vector with Page Number and Inode Size is stored in the 16 byte initialization vector. For Encryption, the output file's inode number is added in the initializatin vector. On the opposite, for Decryption, the input file's inode number is used.
		
		In Cipher Block Chaining Mode, the Initialization Vector is initialized each time before use. So, the format of encrypted or decrypted will be Encrypted Key followed by IV followed by our Cipher text(converted from plain text) and then padding. Padding for kencrypt() and kdecrypt() based on ceph_aes_encrypt() will be 0x10.
		
-------------------
USER MODULE DESIGN
-------------------
	
	* PASSWORD CHECK :
		 a. Passphrase should not be less than 6 characters
		 
		 b. Passphrase is checked for new line character
		 
		 c. If New line character is present, check_string() will remove all the '\n' new line characters from the passphrase.
		 
	* MD5 :
		a. MD5 algorithm is implemented from OpenSSL library. It will return the hashed value of passphrase in an output form of 16 byte digest. This will be sent to the kernel space.
		
		b. Use openssl/md5 header file.

		
	* SYSTEM CALL :
		a. System Call will be called by syscall(int number, arguments to be passed) format. 
		
		b. System call number to be called will be defined in the header file, in our case,
				# define __sys_xcrypt 349

				
	* FORMAT FOR INVOKING SYSCALL SYS_XCRYPT()
		a. Format will be based on Flags and getopt() is used for passing the command line arguments to the user program.
		
		b. Specify -d to decrypt
				   -e to encrypt
				   -p to specify password
				   -h for help
				   and pass infile and outfile after the -d and -e flags.
				   Make sure that you dont pass -d and -e at once!
				   
		c. For Help, use the flag -h.
		


-----------------------
STRUCTURE FOR ARGUMENTS
-----------------------

	* Infile and Outfile represent the infile and outfile respectively
	
	* Key's Length will be 16 as our program uses MD5 for hashing
	
	* Key Buffer for storing data
	
	* Flag for Encryption or Decryption 
				
			 typedef struct _karguments
			 {
					 char infile[SIZE_];
					  char outfile[SIZE_];
					  int key_length;
					  unsigned char key_buffer[SIZE+1];
					  int flag;
			 }       karguments;


			 
---------------------------
EVALUATING THE SOURCE CODE
---------------------------

	
	* In sys_Xcrypt directory, 'make' the source code and find 2 executables as said before - 'sys_xcrypt.ko' and 'xcipher'.
	
	* Then, Insert the module using "insmod sys_xcrypt.ko" and then create an input file for encryption/decryption.
	
	* For Removing the module use "rmmod sys_xcrypt.ko".
	
