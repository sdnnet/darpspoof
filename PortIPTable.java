package net.floodlightcontroller.sdn_arp_spoof_detection;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.VlanVid;

public class PortIPTable{
	private HashMap<DatapathId,HashMap<OFPort,ArrayList<VlanIPPair>>> map;
	public PortIPTable(){
		map = new HashMap<>();
	}
	public boolean addEntry(DatapathId id,OFPort port,VlanIPPair pair){
		HashMap<OFPort,ArrayList<VlanIPPair>> internalMap = map.get(id);
		if(internalMap == null){
			map.put(id,new HashMap<>());
			internalMap = map.get(id);
		}
		ArrayList<VlanIPPair> list = internalMap.get(port);
		if(list == null){
			internalMap.put(port,new ArrayList<>());
			list = internalMap.get(port);
		}
		boolean exist = false;
		exist = (vlanExists(id,port,pair.getVid()));
		list.add(pair);
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
			HashMap<OFPort,ArrayList<VlanIPPair>> internalMap = map.get(id);
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
			HashMap<OFPort,ArrayList<VlanIPPair>> internalMap = map.get(id);
			exist = exist && (internalMap != null);
			if(exist){
				ArrayList<VlanIPPair> list = internalMap.get(port);
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
	public boolean remove(DatapathId id,OFPort port,VlanVid vid){
		boolean exist = map.containsKey(id);
		if(exist){
			HashMap<OFPort,ArrayList<VlanIPPair>> internalMap = map.get(id);
			exist = exist && (internalMap != null);
			if(exist){
				ArrayList<VlanIPPair> list = internalMap.get(port);
				exist = exist && (list != null);
				if(exist){
					remove(list,vid);
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
	}
	private boolean remove(ArrayList<VlanIPPair> list,VlanVid vid){
		VlanIPPair tmpPair = null;
		Iterator<VlanIPPair> itr = list.iterator();
		while(itr.hasNext()){
			VlanIPPair pair = itr.next();
			if(pair.getVid() == vid) {
				tmpPair = pair;
				break;
			}
		}
		if(tmpPair == null) return false;
		list.remove(tmpPair);
		return true;
	}
	/*
	private boolean remove(ArrayList<VlanIPPair> list,IPv4Address addr){
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
		if(!switchExists(id)) return false;
		HashMap<OFPort,ArrayList<VlanIPPair>> internalMap = map.get(id);
		if(internalMap.containsKey(port)) return true;
		return false;
	}
	public boolean vlanExists(DatapathId id, OFPort port,VlanVid vid){
		if(!switchExists(id)) return false;
		HashMap<OFPort,ArrayList<VlanIPPair>> internalMap = map.get(id);
		if(!internalMap.containsKey(port)) return false;
		ArrayList<VlanIPPair> list = internalMap.get(port);
		for(VlanIPPair pair : list){
			if(pair.getVid() == vid) return true;
		}
		return false;
	}
	public boolean IPExists(DatapathId id,OFPort port, IPv4Address addr){
		if(!switchExists(id)) return false;
		HashMap<OFPort,ArrayList<VlanIPPair>> internalMap = map.get(id);
		if(!internalMap.containsKey(port)) return false;
		ArrayList<VlanIPPair> list = internalMap.get(port);
		for(VlanIPPair pair : list){
			if(pair.getIP() == addr) return true;
		}
		return false;
	}
	public IPv4Address getIpForVlan(DatapathId id,OFPort port, VlanVid vid){
		HashMap<OFPort,ArrayList<VlanIPPair>> internalMap = map.get(id);
		if(internalMap == null) return null;
		ArrayList<VlanIPPair> list = internalMap.get(port);
		if(list == null) return null;
		for(VlanIPPair pair : list){
			if(pair.getVid() == vid){
				return pair.getIP();
			}
		}
		return null;
	}
	public MacAddress getMacForVlan(DatapathId id,OFPort port, VlanVid vid){
		HashMap<OFPort,ArrayList<VlanIPPair>> internalMap = map.get(id);
		if(internalMap == null) return null;
		ArrayList<VlanIPPair> list = internalMap.get(port);
		if(list == null) return null;
		for(VlanIPPair pair : list){
			if(pair.getVid() == vid){
				return pair.getMac();
			}
		}
		return null;
	}
}
