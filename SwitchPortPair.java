package net.floodlightcontroller.sdn_arp_spoof_detection;

import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.OFPort;


public class SwitchPortPair{
	private DatapathId sw;
	private OFPort port;
	public SwitchPortPair(DatapathId sw,OFPort port){
		this.sw = sw;
		this.port = port;
	}

	/**
	 * @return the sw
	 */
	public DatapathId getSwitch() {
		return sw;
	}

	/**
	 * @param sw the sw to set
	 */
	public void setSwitch(DatapathId sw) {
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

	@Override
	public String toString(){
		return sw.toString() + " -----> " + port.toString();
	}

}
