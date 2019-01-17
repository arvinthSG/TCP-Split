#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include<iostream>
#include<list>
#include<map>
#include<time.h>
#include<iterator>
#include<memory.h>
#include<string>
#include<stdlib.h>
#include<algorithm>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


using namespace std;

list<struct PacketStruct> unwantedData; //NON-TCP Packet.
list<string> packetOrder; // Save the packet Order. Used when writing the packets to file.
map<string, list<struct PacketStruct>> tcpConnectionMap; //Hash Map of IpCombination and Packets list.
char* outputPath;
int lastfile =0;
int filterIPGiven = 0;
int outputPathGiven = 0;
pcap_t *descr; //Handle to read and write .pcap files
char* filterIP;
int filePathGiven = 0;



/*
Structure to store the parsed packet.
pkthdr - Header of the packet
data - Packet
*/
struct PacketStruct{
	struct pcap_pkthdr* pkthdr;
	u_char* data;
};


void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* data);

/*
Forms a string to be stored in HashMap tcpConnectionMap
Input arguments - source IP, Destination IP, source port number, destination port number.
*/
char * createHashStr(char *src_ip, char *dest_ip, int src_port, int dest_port){	
	int size =strlen(src_ip)+strlen(dest_ip)+sizeof(int)+sizeof(int);
	char * res = (char *) malloc(size);
	if(strcmp(src_ip,dest_ip)>=0){
		snprintf(res,size,"%s%d%s%d",src_ip,src_port,dest_ip,dest_port);
	}else{
		snprintf(res,size,"%s%d%s%d",dest_ip,dest_port,src_ip,src_port);
	}
	
	return res;

}

/*
Inserts data into the tcpConnectionMao
packer - holds the packet,
addr - hash key
*/
void insertData(struct PacketStruct packet, string addr){
	if(tcpConnectionMap.count(addr)){ //Same as containsKey()
		list<struct PacketStruct> temp = tcpConnectionMap.at(addr);
		temp.push_back(packet);
		tcpConnectionMap[addr]=temp;
	}else{
		list<struct PacketStruct> temp;
		temp.push_back(packet);
		tcpConnectionMap[addr]=temp;
	}

	list<string>::iterator it;
	it = find(packetOrder.begin(), packetOrder.end(),addr);
	if(it == packetOrder.end()){
		packetOrder.push_back(addr);	
	}
}

/*
Dumps list of packets into the given file.
 Steps:
 1. Get file pointer.
 2. Get o_handle from pcap_open_dead
 3. Get otrace_handle from pcap_dump_fopen
 4. Iterate through list and pcap_dump
 5. pcap_dump_flush followed by pcap_dump_close.
*/	
void dumpPcap(list<struct PacketStruct> res,pcap_t* descr,char* filename){	
	struct PacketStruct savedPacket;
	pcap_t* o_handle = NULL;
	pcap_dumper_t* otrace_handle = NULL;
	FILE* otracefile = fopen(filename,"w");
	o_handle = pcap_open_dead(pcap_datalink(descr),65535);
	otrace_handle = pcap_dump_fopen(o_handle,otracefile);
	list <struct PacketStruct> :: iterator it; 
	int size = res.size();
	printf("\nWriting file %s",filename);
	for(it = res.begin(); it != res.end(); ++it){
		savedPacket = *it;
		pcap_dump((u_char*)otrace_handle,savedPacket.pkthdr,savedPacket.data);
	}
	pcap_dump_flush(otrace_handle);
	pcap_dump_close(otrace_handle);

}

/*
Function to write the packets to each file
*/
void writeTcpLoopFunc(pcap_t* descr){
	int count = 0;
	list<string>::iterator itr;
	string addr;
	for(itr = packetOrder.begin();itr != packetOrder.end(); ++itr){
		addr = *itr;
		if(tcpConnectionMap.count(addr)){
			list<struct PacketStruct> packetsList = tcpConnectionMap.at(addr);
			char filename[packetOrder.size()+strlen(outputPath)+6]; //size of count + output dir size + ".pcap" size
			snprintf(filename,sizeof(filename),"%s%d.pcap",(char*)outputPath,count);
			dumpPcap(packetsList,descr,filename);
			count++;		
		}
	}
	lastfile = count;
}



/*
Recursive mkdir loop
*/
void makeDir(char* dir) {
	
	char tmp[256];
        char *p = NULL;
        size_t len;

        snprintf(tmp, sizeof(tmp),"%s",dir);
        len = strlen(tmp);
        if(tmp[len - 1] == '/')
                tmp[len - 1] = 0;
        for(p = tmp + 1; *p; p++)
                if(*p == '/') {
                        *p = 0;
                        mkdir(tmp, S_IRWXU);
                        *p = '/';
                }
        mkdir(tmp, S_IRWXU);
}

void getOutputPath(char * dirPath){
	struct stat st = {0};

	if (stat(dirPath, &st) == -1) {
	    makeDir(dirPath);
	}
	outputPath = (char*)malloc(strlen(dirPath));
	snprintf(outputPath,strlen(dirPath)+2,"%s/",dirPath);
}


int main(int argc, char **argv) {
	
	char* filename;
	char* directoryPath;
	int writeNonTcp = 0;
	 
/*
Command line arguments.
-i file_path: (Mandatory) Specifies a pcap file as input.
-o directory_path: (Mandatory) Specifies a directory to output pcap files to.
-f src_ip: (Optional) If this option is given, ignore all traffic that is not from the specified source IP.
-j file_path: (Optional) If this option is given, all non-TCP traffic should be stored into a single pcap file. Otherwise, all non-TCP traffic should be ignored.
*/
	for(int i =0; i<argc;i++){
		printf("\n %s", argv[i]);
		if(strcmp(argv[i],"-i") == 0){
			filename = argv[++i];
			filePathGiven = 1;
		}else if(strcmp(argv[i],"-o") == 0){
			getOutputPath(argv[++i]);
			outputPathGiven = 1;
		}else if(strcmp(argv[i],"-f") == 0){
			filterIP = argv[++i];
			filterIPGiven = 1;
		}else if(strcmp(argv[i],"-j") == 0){
			writeNonTcp = 1;		
		}	
	}
	if(filePathGiven==0 ||outputPathGiven ==0){
		printf("Input parameters missing.\n-i and -o mandatory");		
		return 0;
	}
 	if(!outputPathGiven){
		outputPath = (char*)malloc(2);
		outputPath="";
	}
	char errbuf[PCAP_ERRBUF_SIZE];  // Size defined in pcap.h	    
	printf("Opening file...\n");
	descr = pcap_open_offline(filename, errbuf); // open capture file for offline processing
	if (descr == NULL) {
		printf("open failed %s\n",errbuf);
		return 1;
	}
	if (pcap_loop(descr, 0, packetHandler, NULL) < 0) {
		printf("Pcap loop fail%s\n",pcap_geterr(descr));
		return 1;
	}

	printf("Parsing Packets Completed...\nWriting Process Started...\n");

	writeTcpLoopFunc(descr);

	char nonTcpFilename[packetOrder.size()+strlen(outputPath)+6];
	snprintf(nonTcpFilename,sizeof(nonTcpFilename),"%s%d.pcap",(char*)outputPath,(int)lastfile);
	if(writeNonTcp){
		printf("\nDumping Non TCP data...");
		dumpPcap(unwantedData,descr,nonTcpFilename);
	}

	return 0;

}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* data) {

	//Get Source and destination Address
	int offset = 26; /* 14 bytes for MAC header +
		          * 12 byte offset into IP header for IP addresses
		          */
	char * src_ip = (char*)malloc(16);
	char * dest_ip = (char*)malloc(16);
	snprintf(src_ip,16,"%d.%d.%d.%d",data[offset], data[offset+1], data[offset+2], data[offset+3]);
	
	if (pkthdr->caplen < 30) {
		/* captured data is not long enough to extract IP address
		fprintf(stderr,"Error: not enough captured packet data present to extract IP addresses.\n"); */
		return;
	}
	

	if (pkthdr->caplen >= 34) {
		 // Destination Address
		snprintf(dest_ip,16,"%d.%d.%d.%d",data[offset+4], data[offset+5], data[offset+6], data[offset+7]);
	
	}
	//Skip packets not having given filter IP	
	if(filterIPGiven && ((strcmp(src_ip, filterIP)!=0) && (strcmp(dest_ip, filterIP)!=0))){
		return;
	}
	
	char* timeStamp = ctime((const time_t*)&pkthdr->ts);
//	printf("Total packet available: %d bytes\n", pkthdr->caplen);
//	printf("Expected packet size: %d bytes\n", pkthdr->len);
//	printf("TimeStampe : %s\n",timeStamp);

	const u_char *ip_header;
	const u_char *tcp_header;
	const u_char *payload;

	/* Header lengths in bytes */
	int ethernet_header_length = 14; /* Doesn't change */
	int ip_header_length;
	int tcp_header_length;
	int payload_length;

	
	ip_header = data + ethernet_header_length; // start of IP header 
	ip_header_length = ((*ip_header) & 0x0F);
	ip_header_length = ip_header_length * 4; // The IHL is number of 32-bit segments. Multiply by four to get a byte count for pointer arithmetic 

	u_char protocol = *(ip_header + 9); // We inspect the IP header for a protocol number to make sure it is TCP. Protocol is always the 10th byte of the IP header 
	if (protocol != IPPROTO_TCP) { //NOT TCP - Save to unwantedData list
//		printf("Not a TCP packet. Skipping...\n\n"); 
		struct PacketStruct tempPacketStruct;
		tempPacketStruct.pkthdr = (struct pcap_pkthdr*)malloc(sizeof(struct pcap_pkthdr));
		tempPacketStruct.data = (u_char*)malloc(pkthdr->len);		
		memcpy(tempPacketStruct.pkthdr,pkthdr,sizeof(struct pcap_pkthdr));
		memcpy(tempPacketStruct.data,data,pkthdr->len);		
		unwantedData.push_back(tempPacketStruct);
		return;
	}

	tcp_header = data + ethernet_header_length + ip_header_length;	// Add the ethernet and ip header length to the start of the packetto find the beginning of the TCP header 
	struct tcphdr* tcp = (struct tcphdr*) tcp_header;
	
	int srcPort = ntohs(tcp ->source); //Source Port Number
	int destPort = ntohs(tcp ->dest); // Destination Port Number
 	
	char *addr = createHashStr(src_ip,dest_ip,srcPort,destPort);
	
	struct PacketStruct tempPacketStruct;
	tempPacketStruct.pkthdr = (struct pcap_pkthdr*)malloc(sizeof(struct pcap_pkthdr));
	tempPacketStruct.data = (u_char*)malloc(pkthdr->len);		
	memcpy(tempPacketStruct.pkthdr,pkthdr,sizeof(struct pcap_pkthdr));
	memcpy(tempPacketStruct.data,data,pkthdr->len);		
	insertData(tempPacketStruct,addr);
}
