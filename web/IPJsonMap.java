package net.floodlightcontroller.sdn_arp_spoof_detection.web;

import java.util.HashMap;

import org.projectfloodlight.openflow.types.IPv4Address;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import net.floodlightcontroller.core.IOFSwitch;
@JsonSerialize(using=IPJsonSerializer.class)
public class IPJsonMap{
	private HashMap<IPv4Address,IOFSwitch> map;
	public IPJsonMap(HashMap<IPv4Address,IOFSwitch> map){
		this.map = map;
	}
	public HashMap<IPv4Address,IOFSwitch> getMap(){
		return map;
	}
}
