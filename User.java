package net.floodlightcontroller.sdn_arp_spoof_detection;

import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;

import net.floodlightcontroller.core.IOFSwitch;

public class User {
	private MacAddress mac;
	private IOFSwitch connectedSwitch;
	private OFPort port;
	public User(MacAddress mac,OFPort port, IOFSwitch connectedSwitch) {
		this.mac = mac;
		this.port = port;
		this.connectedSwitch = connectedSwitch;
	}
	public MacAddress getMac() {
		return mac;
	}
	public OFPort getPort() {
		return port;
	}
	public IOFSwitch getConnectedSwitch() {
		return connectedSwitch;
	}
	public void setMac(MacAddress mac) {
		this.mac = mac;
	}
	public void setPort(OFPort port) {
		this.port = port;
	}
	public void setConnectedSwitch(IOFSwitch sw) {
		connectedSwitch = sw;
	}
	@Override
	public boolean equals(Object obj){
		if(obj instanceof User){
			User user = (User) obj;
			return (mac.equals(user.mac) && connectedSwitch.equals(user.connectedSwitch) && port.equals(user.port));
		}
		return false;
	}
}
