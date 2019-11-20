# SDN ARP SPOOF DETECTION
This is floodlight module aiming to detect and avoid arp spoofing using the SDN technology.

### Techniques 
**Mac Based Authentication**
	In this technique we authenticate using the fact that one device connected in network can only have one MAC address. So, we cannot get any packet from an input port with different mac addresses.
	To deal with a device can change on a switch port we delete the flows of that port if we do not recieve any flow on that port for a specified time.
