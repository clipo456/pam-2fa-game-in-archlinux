

forca.o: forca.c
	gcc -fPIC -fno-stack-protector -c forca.c

install: forca.o
	ld -x --shared -o /lib64/security/forca.so forca.o

uninstall:
	rm -f /lib64/security/forca.so
	@echo -e "\n\n      Remove any entry related to this module in /etc/pam.d/ files,\n      otherwise you're not going to be able to login.\n\n"
debug:
	gcc -E -fPIC -fno-stack-protector -c forca.c
clean:
	rm -rf *.o
