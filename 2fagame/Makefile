

2fagame.o: 2fagame.c
	gcc -fPIC -fno-stack-protector -c 2fagame.c

install: 2fagame.o
	ld -x --shared -o /lib64/security/2fagame.so 2fagame.o

uninstall:
	rm -f /lib64/security/2fagame.so
	@echo -e "\n\n      Remove any entry related to this module in /etc/pam.d/ files,\n      otherwise you're not going to be able to login.\n\n"
debug:
	gcc -E -fPIC -fno-stack-protector -c 2fagame.c
clean:
	rm -rf *.o
