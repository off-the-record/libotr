all:
	gcc dummy_client.c -DOTR30  -g -o dummy_client_30  -Wl,-Bstatic -I/home/rdfsmits/otr/cvs-3.0/libotr/src -L./libs -lotr3.0 -Wl,-Bdynamic -lpthread  -lgcrypt -lgpg-error
	gcc dummy_client.c -DOTR31  -g -o dummy_client_31  -Wl,-Bstatic -I/home/rdfsmits/otr/cvs-3.1/libotr/src -L./libs -lotr3.1 -Wl,-Bdynamic -lpthread  -lgcrypt -lgpg-error
	gcc dummy_client.c -DOTR32  -g -o dummy_client_32  -Wl,-Bstatic -I/home/rdfsmits/otr/cvs-3.2/libotr/src -L./libs -lotr3.2 -Wl,-Bdynamic -lpthread  -lgcrypt -lgpg-error
	gcc dummy_client.c -DOTR40  -g -o dummy_client_40  -Wl,-Bstatic -I/home/rdfsmits/otr/git/otr/libotr/src -L./libs -lotr4.0 -Wl,-Bdynamic -lpthread  -lgcrypt -lgpg-error
clean:
	rm dummy_client_30 dummy_client_31 dummy_client_32 dummy_client_40 

