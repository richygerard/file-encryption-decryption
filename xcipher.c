/*
 * xCipher Driver Program
 * to Test System Call sys_xcrypt() to Encrypt & Decrypt files
 */

#include "xcipher.h"

int main(int argc, char* argv[])
{
	char passphrase[SIZE+SIZE], *checked_passphrase;
	unsigned char pass_hash[SIZE+1];
	int checked_passphrase_length=0;
	int result = 0;

	/* Buffer which takes the User Arguments to Kernel  */	
	void *buffer = (void *) malloc (sizeof(karguments));

	/* User arguments Passed to the Kernel Buffer */
	karguments *kargs = (karguments *) malloc (sizeof(karguments));

	/* Case Selection of input flags */
	int case_p = 0;
	int case_e = 0;
	int case_d = 0;
	int case_h = 0;

	int ch;
	opterr = 0;

	/* Using getopt for flag selection */
	while((ch = getopt (argc, argv, "p:edh")) != -1) {
		switch(ch) {
			/* Case '-p' flag : Password */
			case 'p' :
				case_p = 1;

				if((strlen(optarg) < 6)) { 
					perror("Length of Passphrase is less \
								 than 6.\n");
					goto exit;
				}

				if((strlen(optarg) > (SIZE+SIZE))) { 
					perror("Length of Passphrase is too \
								 long.\n");
					goto exit;
				}

				strcpy(passphrase, optarg);
				if(!(checked_passphrase = check_string \
							(passphrase))) {
					perror("Error in String Checking.\n");
					goto exit;
				}

				checked_passphrase_length = strlen \
							(checked_passphrase);

				/* Generating the MD5 Digest for the Passphrse */
				MD5((unsigned char*) passphrase, \
					checked_passphrase_length , pass_hash);
				
				#ifdef DEBUG
					printf("Printing the Hash Value of \
								Passphrase : ");
					print_md5(pass_hash);
				#endif

				strncpy((char *)kargs->key_buffer, (char *) \
								pass_hash, SIZE);
				kargs->key_length = strlen((char *)kargs-> \
							key_buffer);
				break;
			
			/* Case '-e' flag : Encryption */		
			case 'e' :
				case_e = 1;
				break;

			/* Case '-d' flag : Decryption */		
			case 'd' :
				case_d = 1;
				break;
	
			/* Case '-h' flag : Help */		
			case 'h' :
				case_h = 1;
				break;
	
			case '?' :
			/* Case '-?' flag : Other Arguments */		
				if (optopt == 'p')
					perror ("Option '-p' requires argument. \
						Use '-h' flag for Help.\n");
				else 
					perror ("Unknown option character.\n");
				goto exit;
	
			default :
				printf ("Bad Command Line Arguments. \
						 Use '-h' flag for Help.\n");
				goto exit;
		}
	}

	if ((argc<=5) || (argc>7))  {
		perror("Bad Command Line Arguments. Use flag -h for Help.\n");
		goto exit;

	}

	#ifdef DEBUG
		printf ("Passphrase : optarg : %s\n", passphrase);
		printf ("Optind :%d, Argument : %s\n", optind, argv[optind]);
		printf ("Optind+1 :%d,Argument: %s\n", optind+1, argv[optind+1]);
	#endif

	if ((case_e == 1) && (case_d == 1)) {
		perror("Encryption & Decryption Specified the same time.\n");
		goto exit;
	}
	/* Encryption */
	if (case_e == 1) {
		kargs->flag = 1;
	}

	/* Decryption */
	else if (case_d == 1) {
		kargs->flag = 0;
	}


	strncpy(kargs->infile, argv[optind], strlen(argv[optind]));
     	strncpy(kargs->outfile, argv[optind+1], strlen(argv[optind+1]));

	/* Help */
	if (case_h == 1) {
		print_help();
	}

	#ifdef DEBUG
		printf("\n1. Infile : %s\n2. Outfile : %s\n3. Key Length : %d\n \
				4. Flag : %d\n",kargs->infile,kargs->outfile, \
						kargs->key_length,kargs->flag);
	#endif

	/* Copying the Kernel Arguments to the Buffer */
	memcpy((void *) buffer, (void *) kargs, sizeof(karguments)); 

	/* System Call Invocation */
	result = sys_xcrypt(__sys_xcrypt, buffer);

	#ifdef DEBUG
		printf("System Call xCrypt is Invoked & returned %d\n",\
								 (int)result);
	#endif

	free(kargs);
	free(buffer);
	return 0;

	exit :
		if (kargs)
			free(kargs);
		if (buffer)
			free(buffer);
		return -1;
}


/*
 * print_md5() prints the MD5 Digest of the Input MD5 Hash
 */
void print_md5(unsigned char *mess_dig) {
	int i;
	for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
		printf("%02x", mess_dig[i]);
	}
	printf("\n");
}

/* 
 * Checking the String for Possible errors in passphrase
 * Removes the New Line Character and returns the string.
 */
char *check_string(char *string) 

{
	char *checked_string;
	int i=0, j=0;

	if (!(checked_string = (char *) malloc (strlen(string) + 1))) {
		perror("Malloc Failed.\n");
		goto exit;
	}

	if (strlen(string)<6) {
		perror("Password Less than 6. Use flag '-h' for help.\n");
		return NULL;
	}

	/* String checked for New Line Character */
	while (string[i]) {
		if (string[i] != '\n') {
		checked_string[j] = string[i];
		j++;
		}
	i++;
	}
	checked_string[j] = '\0';

	#ifdef DEBUG
		printf("Checked String is : '%s'\n ", checked_string);
	#endif

	strncpy(string, checked_string, j);
	free(checked_string);
	return string;

	exit :
		if (checked_string)
			free(checked_string);
		return NULL;

}

/*
 * pring_help() prints the Help Information
 */
void print_help() {
	printf("		Welcome to Help v1.0 \n\
		Command Line Argument Help \n\
		Run the executable with the following format \n\
		./xcipher -p  \"YOUR PASSWORD \" -e input_file output_file \n\n\
		The Flags are given below \n\
		Flag -e : To Encrypt	\n\
		Flag -d : To Decrypt	\n\
		Flag -p : To Specify password	\n\
		Flag -h : For Help	\n\
		Use any one Flag : -e / -d to encrypt/decrypt and then\
		specify the input and output files correctly.");
}
