pcap: pcap.o
	gcc -o pcap pcap.o -lpcap
pcap.o: pcap.c header.h
	gcc -c pcap.c
