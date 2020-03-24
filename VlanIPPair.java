package net.floodlightcontroller.sdn_arp_spoof_detection;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.VlanVid;

public class VlanIPPair{
	private VlanVid vid;
	private IPv4Address address;
	public VlanIPPair(VlanVid vid,IPv4Address address){
		this.vid = vid;
		this.address = address;
	}
	public void setVid(VlanVid vid){
		this.vid = vid;
	}
	public void setIP(IPv4Address ip){
		this.address = ip;
	}
	public VlanVid getVid(){
		return vid;
	}
	public IPv4Address getIP(){
		return address;
	}
	@Override
	public boolean equals(Object obj){
		if(!(obj instanceof VlanIPPair)) return false;
		VlanIPPair tmp = (VlanIPPair) obj;
		return (tmp.address == address && tmp.vid == vid);
	}

}
