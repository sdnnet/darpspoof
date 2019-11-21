package net.floodlightcontroller.sdn_arp_spoof_detection;

import org.projectfloodlight.openflow.types.OFPort;

import net.floodlightcontroller.core.IOFSwitch;

public class User<T> {
	private T address;
	private IOFSwitch connectedSwitch;
	private OFPort port;
	public User(T address,OFPort port, IOFSwitch connectedSwitch) {
		this.address = address;
		this.port = port;
		this.connectedSwitch = connectedSwitch;
	}
	public T getAddress() {
		return address;
	}
	public OFPort getPort() {
		return port;
	}
	public IOFSwitch getConnectedSwitch() {
		return connectedSwitch;
	}
	public void setAddress(T address) {
		this.address = address;
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
			@SuppressWarnings("unchecked")
			User<T> user = (User<T>) obj;
			return (address.equals(user.address) && connectedSwitch.equals(user.connectedSwitch) && port.equals(user.port));
		}
		return false;
	}
}
