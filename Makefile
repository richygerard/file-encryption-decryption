obj-m	+= sys_xcrypt.o

CC = gcc
all:
	clear
	make -Wall -Werror -C /lib/modules/3.2.2+/build/ M=$(PWD) modules
	gcc -Wall -Werror -g -O2 -o xcipher.o -c xcipher.c
	gcc -Wall -Werror -g -O2 -o xcipher xcipher.o -lssl

remove :
	rmmod sys_xcrypt.ko

insert :
	insmod sys_xcrypt.ko

e:

	./xcipher -p password -e in out

d:

	./xcipher -p password -d out in

xcipher: xcipher.o

	${CC} -g -O2 -o xcipher xcipher.o -lssl

xcipher.o: xcipher.c

	${CC} -g -O2  -c xcipher.c -lssl

clean:
	make -C /lib/modules/3.2.2+/build/ M=$(PWD) clean
	rm xcipher
