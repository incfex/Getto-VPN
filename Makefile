all: vpnC vpnS
	
vpnC: vpnC.c shadowAuth.c
	gcc -g -Wall vpnC.c -lpthread -lssl -lcrypto -lcrypt -o vpnC
vpnS: vpnS.cc shadowAuth.c
	g++ -g -Wall vpnS.cc -lpthread -lssl -lcrypto -lcrypt -o vpnS
clean:
	rm vpnC vpnS
