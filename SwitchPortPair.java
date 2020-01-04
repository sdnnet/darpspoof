package net.floodlightcontroller.sdn_arp_spoof_detection;

import org.projectfloodlight.openflow.types.OFPort;

import net.floodlightcontroller.core.IOFSwitch;

public class SwitchPortPair{
	private IOFSwitch sw;
	private OFPort port;
	public SwitchPortPair(IOFSwitch sw,OFPort port){
		this.sw = sw;
		this.port = port;
	}

	/**
	 * @return the sw
	 */
	public IOFSwitch getSwitch() {
		return sw;
	}

	/**
	 * @param sw the sw to set
	 */
	public void setSwitch(IOFSwitch sw) {
		this.sw = sw;
	}

	/**
	 * @return the port
	 */
	public OFPort getPort() {
		return port;
	}

	/**
	 * @param port the port to set
	 */
	public void setPort(OFPort port) {
		this.port = port;
	}
	@Override
	public boolean equals(Object ob){
		if(ob instanceof SwitchPortPair){
			SwitchPortPair ref = (SwitchPortPair) ob;
			if(ref.sw.equals(sw) && ref.port.equals(port)) return true;
		}
		return false;
	}

}
