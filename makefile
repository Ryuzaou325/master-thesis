MAKEFLAGS += -B

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

METRICS = metrics/*.o

ALGORITHMS = algorithms/*.o

benchmark: benchmark.c
	#$(MAKE) -C ./libs/ascon/ascon/build
	$(MAKE) -C ./algorithms
	$(MAKE) -C ./metrics
	gcc -o benchmark benchmark.c -march=native -O3 -lpthread $(METRICS) $(ALGORITHMS) $(SIPHASH_SOURCES) $(5G_SOURCES) $(ASCON_SOURCES) $(LIBSODIUM_SOURCES)

	
