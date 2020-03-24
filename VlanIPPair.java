package net.floodlightcontroller.sdn_arp_spoof_detection;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.VlanVid;

public class VlanIPPair{
	private VlanVid vid;
	private IPv4Address address;
	private MacAddress mac;
	public VlanIPPair(VlanVid vid,IPv4Address address,MacAddress mac){
		this.vid = vid;
		this.address = address;
		this.mac = mac;
	}
	public void setVid(VlanVid vid){
		this.vid = vid;
	}
	public void setIP(IPv4Address ip){
		this.address = ip;
	}
	public void setMac(MacAddress mac){
		this.mac = mac;
	}
	public VlanVid getVid(){
		return vid;
	}
	public IPv4Address getIP(){
		return address;
	}
	public MacAddress getMac(){
		return mac;
	}
	@Override
	public boolean equals(Object obj){
		if(!(obj instanceof VlanIPPair)) return false;
		VlanIPPair tmp = (VlanIPPair) obj;
		return (tmp.address == address && tmp.vid == vid && tmp.mac == mac);
	}

}
