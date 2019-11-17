package net.floodlightcontroller.arp_detect;

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
}
