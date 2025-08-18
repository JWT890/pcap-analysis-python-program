# pcap-analysis-python-program
For use download a sample Wireshark file from here: https://wiki.wireshark.org/samplecaptures, or add your own.  

Analyzing PCAP files from Wireshark can show analysts to examine raw traffic flowing through a network and is important in network troubleshooting. The Wireshark tool provides a GUI for this task of analying the file from capture to inspection in real time.  
This allows for inspection and analysis of any suspicious activity to monitor network performance, detection of port scan anomalies, unauthorized connections, unusual packets.  
This allows to quickly foloow specific traffic like DNS queries and HTTP requests and important for incident response and day-to-day monitoring.  

With Python this allows for greater analysis of a PCAP file using libraries such as Scapy, PyShark, and dpkt to parse PCAP files, extract key fields like IPs and protocols for analysis or visualization. Combining both Wireshark analysis and Python can make things easier with the extraction of key fields to aid analysts.   

To get this program to run, add a Wireshark file to the pcaps file:  
<img width="497" height="177" alt="image" src="https://github.com/user-attachments/assets/eec454b0-d4f9-45eb-8fc2-d5066209615f" />  
And type the command: python pcap_analyzer.py, to get the program to run the checker on the file.  
Example of output in the command console:  
<img width="1133" height="226" alt="image" src="https://github.com/user-attachments/assets/93d7ac94-130f-4551-be56-bacadcb797d4" />  
The program will also visualize the traffic from the file and output it for visualization  
Example:  
<img width="1200" height="600" alt="Figure_1" src="https://github.com/user-attachments/assets/555278ec-7b92-46f6-ad43-bb6e5aef84a0" />


