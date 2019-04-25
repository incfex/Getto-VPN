all: vpnC vpnS
	
vpnC: vpnC.c
	gcc -g vpnC.c -lpthread -lssl -lcrypto -lcrypt -o vpnC
vpnS: vpnS.c
	gcc -g vpnS.c -lpthread -lssl -lcrypto -lcrypt -o vpnS
clean:
	rm vpnC vpnS
