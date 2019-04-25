all: vpnC vpnS
	
vpnC: vpnC.c
	gcc -g vpnC.c -lpthread -lssl -lcrypto -o vpnC
vpnS: vpnS.c
	gcc -g vpnS.c -lpthread -lssl -lcrypto -o vpnS
clean:
	rm vpnC vpnS
