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
	
LIBSODIUM_SOURCES = -lsodium
	
	


snow3g: snow3g.c
	gcc -o snow3g snow.c $(5G_SOURCES)

siphash: siphash.c
	gcc -o siphash sip.c $(SIPHASH_SOURCES)

ascon: ascon.c
	#$(MAKE) -C ./libs/ascon/ascon/build
	gcc -o ascon ascon.c -march=native -O3 $(ASCON_SOURCES)

aes: aes.c
	gcc -o aes aes.c $(LIBSODIUM_SOURCES)

chachapoly: chachapoly.c
	gcc -o chachapoly chachapoly.c $(LIBSODIUM_SOURCES)
	
salsapoly: salsapoly.c
	gcc -o salsapoly salsapoly.c $(LIBSODIUM_SOURCES)
	
chacha: chacha.c
	gcc -o chacha chacha.c $(LIBSODIUM_SOURCES)

salsa: salsa.c
	gcc -o salsa salsa.c $(LIBSODIUM_SOURCES)

poly: poly.c
	gcc -o poly poly.c $(LIBSODIUM_SOURCES)

hmac: hmac.c
	gcc -o hmac hmac.c $(LIBSODIUM_SOURCES)
	
xor: xor.c
	gcc -o xor xor.c

benchmark: benchmark.c
	#$(MAKE) -C ./libs/ascon/ascon/build
	gcc -o benchmark benchmark.c -march=native -O3 -lpthread $(SIPHASH_SOURCES) $(5G_SOURCES) $(ASCON_SOURCES) $(LIBSODIUM_SOURCES)
	
