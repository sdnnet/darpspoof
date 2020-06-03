package net.floodlightcontroller.sdn_arp_spoof_detection.darpspoof;

import java.util.HashMap;
import java.util.Iterator;

import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.VlanVid;

import net.floodlightcontroller.core.types.NodePortTuple;

public class PortIPTable{
	private HashMap<DatapathId,HashMap<OFPort,VlanIPPair>> map;
	public PortIPTable(){
		map = new HashMap<>();
	}
	public NodePortTuple getSwitchFor(VlanVid vid, IPv4Address addr){
		Iterator<DatapathId> switchItr = map.keySet().iterator();
		while(switchItr.hasNext()){
			DatapathId dpid = switchItr.next();
			HashMap<OFPort,VlanIPPair> internalMap = map.get(dpid);
			Iterator<OFPort> portItr = internalMap.keySet().iterator();
			while(portItr.hasNext()){
				OFPort port = portItr.next();
				VlanIPPair pair = internalMap.get(port);
				if(pair.getIP().equals(addr) && pair.getVid().equals(vid)) return new NodePortTuple(dpid,port);
			}
		}
		return null;
	}
	public boolean addEntry(DatapathId id,OFPort port,VlanIPPair pair){
		HashMap<OFPort,VlanIPPair> internalMap = map.get(id);
		if(internalMap == null){
			map.put(id,new HashMap<>());
			internalMap = map.get(id);
		}
		VlanIPPair tablePair = internalMap.get(port);
		boolean exist = false;
		if(tablePair != null){
			exist = true;
		}
		internalMap.put(port,pair);
		return exist;
	}
	public boolean remove(DatapathId id){
		boolean exist = map.containsKey(id);
		if(exist){
			map.remove(id);
		}
		return exist;
	}
	public boolean remove(DatapathId id,OFPort port){
		boolean exist = map.containsKey(id);
		if(exist){
			HashMap<OFPort,VlanIPPair> internalMap = map.get(id);
			exist = exist && (internalMap != null);
			if(exist){
				internalMap.remove(port);
				if(internalMap.isEmpty()){
					map.remove(id);
				}
			}
		}
		return exist;
	}
	/*
	public boolean remove(DatapathId id,OFPort port,IPv4Address addr){
		boolean exist = map.containsKey(id);
		if(exist){
			HashMap<OFPort,VlanIPPair> internalMap = map.get(id);
			exist = exist && (internalMap != null);
			if(exist){
				VlanIPPair list = internalMap.get(port);
				exist = exist && (list != null);
				if(exist){
					remove(list,addr);
					if(list.isEmpty()){
						internalMap.remove(port);
						if(internalMap.isEmpty()){
							map.remove(id);
						}
					}
				}
			}
		}
		return exist;
	}*/
	/*
	private boolean remove(VlanIPPair list,IPv4Address addr){
		VlanIPPair tmpPair = null;
		Iterator<VlanIPPair> itr = list.iterator();
		while(itr.hasNext()){
			VlanIPPair pair = itr.next();
			if(pair.getIP() == addr) {
				tmpPair = pair;
				break;
			}
		}
		if(tmpPair == null) return false;
		list.remove(tmpPair);
		return true;
	}*/
	public boolean switchExists(DatapathId id){
		return map.containsKey(id);
	}
	public boolean portExists(DatapathId id,OFPort port){
		if(id==null || port == null) return false;
		if(!switchExists(id)) return false;
		HashMap<OFPort,VlanIPPair> internalMap = map.get(id);
		if(internalMap.containsKey(port)) return true;
		return false;
	}
	public boolean vlanExists(DatapathId id, OFPort port,VlanVid vid){
		VlanIPPair pair = getVlanIpPair(id,port);
		if(pair==null) return false;
		if(pair.getVid().equals(vid)) return true;
		return false;
	}
	public boolean IPExists(DatapathId id,OFPort port, IPv4Address addr){
		VlanIPPair pair = getVlanIpPair(id,port);
		if(pair==null) return false;
		if(pair.getIP().equals(addr)) return true;
		return false;
	}
	public VlanIPPair getVlanIpPair(DatapathId id,OFPort port){
		HashMap<OFPort,VlanIPPair> internalMap = map.get(id);
		if(internalMap == null) return null;
		VlanIPPair list = internalMap.get(port);
		return list;
	}
	public MacAddress getMac(DatapathId id,OFPort port){
		VlanIPPair pair = getVlanIpPair(id,port);
		if(pair==null) return null;
		return pair.getMac();
	}
}
