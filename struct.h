/*
 * Sys_xCrypt Header File
 */

#define SIZE 16
#define SIZE_ 60
#define MAX_KEY 1024

/* Structure for Passing Arguments from User space to Kernal Space */
typedef struct _karguments {
	char infile[SIZE_];
	char outfile[SIZE_];
	int key_length;
	unsigned char key_buffer[SIZE+1];
	int flag;
} 	karguments;

