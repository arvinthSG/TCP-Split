# TCP-Split
When a .pcap file is given, the program splits the pcap file into seperate tcp connections and saves them in seperate files.
The program uses libpcap library.

Also, the command line arguments:

-i file_path: (Mandatory) Specifies a pcap file as input.

-o directory_path: (Mandatory) Specifies a directory to output pcap files to.

-f src_ip: (Optional) If this option is given, ignores all traffic that is not from the specified source IP.

-j file_path: (Optional) If this option is given, all non-TCP traffic will be stored into a single pcap file. Otherwise, all non-TCP traffic will be ignored.
