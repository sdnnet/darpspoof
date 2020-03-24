package net.floodlightcontroller.sdn_arp_spoof_detection;

import java.util.HashMap;

import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.VlanVid;

public class MacPortTable{
	private HashMap<MacAddress,HashMap<VlanVid,OFPort>> map;
	public boolean vidExists(MacAddress addr,VlanVid vid){
		HashMap<VlanVid,OFPort> internalMap = map.get(addr);
		if(internalMap == null) return false;
		return internalMap.containsKey(vid);
	}
	public boolean removeVid(MacAddress addr,VlanVid vid){
		HashMap<VlanVid,OFPort> internalMap = map.get(addr);
		if(internalMap == null) return false;
		if(!internalMap.containsKey(vid)) return false;
		internalMap.remove(vid);
		if(internalMap.isEmpty()){
			map.remove(addr);
		}
		return true;
	}
	public boolean deleteMacEntry(MacAddress addr){
		if(!map.containsKey(addr)) return false;
		map.remove(addr);
		return true;
	}
	public boolean addEntry(MacAddress addr,VlanVid vid,OFPort port){
		HashMap<VlanVid,OFPort> internalMap = map.get(addr);
		if(internalMap == null){
			map.put(addr,new HashMap<>());
			internalMap = map.get(addr);
		}
		boolean exist = false;
		if(internalMap.containsKey(vid)) exist = true;
		internalMap.put(vid,port);
		return exist;
	}
}
