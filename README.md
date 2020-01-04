# DETECTION AND AVOIDANCE OF ARP SPOOFING USING SDN
This repository is a floodlight module that aims to detect and block any arp spoofing attack using the concept of Software Defined Networking to make your SDN based network secure and reliable.

## Installation Instructions

### Dependencies
Oracle JDK 8

Floodlight version >= 1.2

git


### Steps
 Go to src/main/java/net/floodlightcontroller folder of floodlight

	git submodule add https://github.com/sdnnet/sdn_arp_spoof_detection

Follow floodlight tutorial to load a module to load ```sdn_arp_spoof_detection/ArpAuthenticator.java```

### Using REST API

This module also lets you to see the ip vs port mapping

You can see it using : ```curl http://<controller-ip>:8080/wm/arp/list```
