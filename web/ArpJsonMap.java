package net.floodlightcontroller.sdn_arp_spoof_detection.web;

import java.util.HashMap;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.OFPort;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import net.floodlightcontroller.core.IOFSwitch;
@JsonSerialize(using=ArpJsonSerializer.class)
public class ArpJsonMap{
	private HashMap<IOFSwitch,HashMap<OFPort,IPv4Address>> map;
	public ArpJsonMap(HashMap<IOFSwitch,HashMap<OFPort,IPv4Address>> map){
		this.map = map;
	}
	public HashMap<IOFSwitch,HashMap<OFPort,IPv4Address>> getMap(){
		return map;
	}
}
