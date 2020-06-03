package net.floodlightcontroller.sdn_arp_spoof_detection.darpspoof;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map.Entry;

import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;

import net.floodlightcontroller.core.types.NodePortTuple;

public class MacPortTable{
	private HashMap<MacAddress,NodePortTuple> map;
	public MacPortTable(){
		map = new HashMap<>();
	}
	public void removeSwitch(DatapathId id){
		Iterator<Entry<MacAddress,NodePortTuple>> itr = map.entrySet().iterator();
		while(itr.hasNext()){
			NodePortTuple tuple = itr.next().getValue();
			if(tuple.getNodeId().equals(id)) {
				itr.remove();
			}
		}
	}
	public boolean removeMac(MacAddress addr){
		boolean exist = map.containsKey(addr);
		if(exist) map.remove(addr);
		return exist;
	}
	public boolean deleteMacEntry(MacAddress addr){
		if(!map.containsKey(addr)) return false;
		map.remove(addr);
		return true;
	}
	public NodePortTuple getPortForMac(MacAddress mac){
		return map.get(mac);
	}
	public boolean addEntry(MacAddress addr,DatapathId dpid,OFPort port){
		boolean exists = map.containsKey(addr);
		map.put(addr,new NodePortTuple(dpid,port));
		return exists;
	}
	public boolean macExists(MacAddress addr){
		return map.containsKey(addr);
	}
}
