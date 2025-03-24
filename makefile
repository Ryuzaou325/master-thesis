OBJ_DIR = ./libs/cryptopp
SRC_FILES = $(wildcard $(OBJ_DIR/*.o))
EXCLUDE_FILE = $(OBJ_DIR)/test.o # This file is compilation problems but is not needed

OBJ_FILES = $(filter-out $(EXCLUDE_FILE), $(SRC_FILES))

SIPHASH_SOURCES = \
	./libs/SipHash/SipHash/halfsiphash.c \
	./libs/SipHash/SipHash/siphash.c \
	-I./libs/SipHash/SipHash/*.h

5G_SOURCES = \
	./libs/snow3g/snow3g/f8.c \
	./libs/snow3g/snow3g/f9.c \
	./libs/snow3g/snow3g/SNOW_3G.c
	
ASCON_SOURCES = \
	-I./libs/ascon/ascon/tests \
	./libs/ascon/ascon/crypto_aead/asconaead128/ref/*.c
	


snow3g: snow.c
	gcc -o snow3g snow.c ./libs/snow3g/snow3g/f8.c ./libs/snow3g/snow3g/f9.c ./libs/snow3g/snow3g/SNOW_3G.c

siphash: sip.c
	gcc -o siphash sip.c ./libs/SipHash/SipHash/halfsiphash.c

ascon: ascon.c
	#$(MAKE) -C ./libs/ascon/ascon/build
	gcc -o ascon ascon.c -march=native -O3 -I./libs/ascon/ascon/tests ./libs/ascon/ascon/crypto_aead/asconaead128/ref/*.c

chachapoly: chachapoly.c
	gcc -o chachapoly chachapoly.c -I./libs/libsodium/libsodium/*.c -I./libs/libsodium/libsodium/*.h

benchmark: benchmark.c
	#$(MAKE) -C ./libs/ascon/ascon/build
	g++ -o benchmark benchmark.c -march=native -O3 -lpthread $(SIPHASH_SOURCES) $(5G_SOURCES) $(ASCON_SOURCES)
