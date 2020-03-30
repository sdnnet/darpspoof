package net.floodlightcontroller.sdn_arp_spoof_detection;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map.Entry;

import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.VlanVid;

import net.floodlightcontroller.core.types.NodePortTuple;

public class MacPortTable{
	private HashMap<MacAddress,HashMap<VlanVid,NodePortTuple>> map;
	public MacPortTable(){
		map = new HashMap<>();
	}
	public boolean vidExists(MacAddress addr,VlanVid vid){
		HashMap<VlanVid,NodePortTuple> internalMap = map.get(addr);
		if(internalMap == null) return false;
		return internalMap.containsKey(vid);
	}
	public boolean removeVid(MacAddress addr,VlanVid vid){
		HashMap<VlanVid,NodePortTuple> internalMap = map.get(addr);
		if(internalMap == null) return false;
		if(!internalMap.containsKey(vid)) return false;
		internalMap.remove(vid);
		if(internalMap.isEmpty()){
			map.remove(addr);
		}
		return true;
	}
	public void removeSwitch(DatapathId id){
		Iterator<Entry<MacAddress,HashMap<VlanVid,NodePortTuple>>> itr = map.entrySet().iterator();
		while(itr.hasNext()){
			HashMap<VlanVid,NodePortTuple> internalMap = itr.next().getValue();
			Iterator<Entry<VlanVid,NodePortTuple>> internalItr = internalMap.entrySet().iterator();
			while(internalItr.hasNext()){
				if(internalItr.next().getValue().getNodeId().equals(id)) internalItr.remove();
			}
			if(internalMap.isEmpty()) itr.remove();
		}
	}
	public boolean deleteMacEntry(MacAddress addr){
		if(!map.containsKey(addr)) return false;
		map.remove(addr);
		return true;
	}
	public NodePortTuple getPortForMac(MacAddress mac,VlanVid vid){
		HashMap<VlanVid,NodePortTuple> internalMap = map.get(mac);
		return internalMap.get(vid);
	}
	public boolean addEntry(MacAddress addr,VlanVid vid,DatapathId dpid,OFPort port){
		HashMap<VlanVid,NodePortTuple> internalMap = map.get(addr);
		if(internalMap == null){
			map.put(addr,new HashMap<>());
			internalMap = map.get(addr);
		}
		boolean exist = false;
		if(internalMap.containsKey(vid)) exist = true;
		internalMap.put(vid,new NodePortTuple(dpid,port));
		return exist;
	}
}
