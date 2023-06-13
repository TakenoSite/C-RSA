
C := gcc 
CFALG := -lssl -lcrypto -Wall -Wextra
CFILE := *.c

rsa:
	$(C) $(CFILE) $(CFALG) -o $@
