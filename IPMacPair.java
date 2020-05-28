package net.floodlightcontroller.sdn_arp_spoof_detection;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;

public class IPMacPair{
	private IPv4Address ip;
	private MacAddress mac;

	public IPMacPair(IPv4Address ip,MacAddress mac){
		this.ip = ip;
		this.mac = mac;
	}
	/**
	 * @return the ip
	 */
	public IPv4Address getIp() {
		return ip;
	}

	/**
	 * @param ip the ip to set
	 */
	public void setIp(IPv4Address ip) {
		this.ip = ip;
	}

	/**
	 * @return the mac
	 */
	public MacAddress getMac() {
		return mac;
	}

	/**
	 * @param mac the mac to set
	 */
	public void setMac(MacAddress mac) {
		this.mac = mac;
	}

	@Override
	public boolean equals(Object ob){
		if(ob instanceof IPMacPair){
			IPMacPair pair = (IPMacPair) ob;
			return (ip.equals(pair.ip) && mac.equals(pair.mac));
		}
		return false;
	}
}
