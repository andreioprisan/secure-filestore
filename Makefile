cstore: cstore.o cstore_list.o cstore_add.o cstore_extract.o cstore_delete.o cstore_utils.o
	g++ -g cstore.o cstore_list.o cstore_add.o cstore_extract.o cstore_delete.o cstore_utils.o -o cstore -std=c++17

cstore.o: cstore.cpp
	g++ -c -g cstore.cpp -std=c++17

cstore_list.o: cstore_list.cpp
	g++ -c -g cstore_list.cpp -std=c++17

cstore_add.o: cstore_add.cpp
	g++ -c -g cstore_add.cpp -std=c++17

cstore_extract.o: cstore_extract.cpp
	g++ -c -g cstore_extract.cpp -std=c++17

cstore_delete.o: cstore_delete.cpp
	g++ -c -g cstore_delete.cpp -std=c++17

cstore_utils.o: cstore_utils.cpp
	g++ -c -g cstore_utils.cpp -std=c++17

sha256.o: crypto_lib/sha256.c
	g++ -c -g crypto_lib/sha256.c -std=c++17

aes.o: crypto_lib/aes.c
	g++ -c -g crypto_lib/aes.c -std=c++17

.PHONY: clean
clean:
	rm *.o cstore

PREFIX = /usr/local
export PATH := $(PREFIX)/bin:$(PATH)
.PHONY: install
install: cstore
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp $< $(DESTDIR)$(PREFIX)/bin/cstore

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/cstore

