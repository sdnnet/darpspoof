package net.floodlightcontroller.sdn_arp_spoof_detection;

import org.projectfloodlight.openflow.types.OFPort;

import net.floodlightcontroller.core.IOFSwitch;

public class SwitchPortPair{
	public IOFSwitch sw;
	public OFPort port;
	SwitchPortPair(IOFSwitch sw,OFPort port){
		this.sw = sw;
		this.port = port;
	}
	@Override
	public boolean equals(Object obj){
		if(obj instanceof SwitchPortPair){
			SwitchPortPair pair = (SwitchPortPair) obj;
			if(sw.equals(pair.sw) && port.equals(pair.port)) return true;
			return false;
		}
		return false;
	}
}
