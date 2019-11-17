package net.floodlightcontroller.arp_detect;

import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;

import net.floodlightcontroller.core.IOFSwitch;

public class MaliciousUser extends User implements Runnable {
	Authenticator authenticator;
	private int blockedTime;//in seconds
	public static final int defaultBlockTime = 10;//in seconds
	private boolean isBlocked;
	public MaliciousUser(MacAddress mac, OFPort port, IOFSwitch connectedSwitch) {
		super(mac, port, connectedSwitch);
		isBlocked = true;
		blockedTime = 10;
	}

	public MaliciousUser(MacAddress mac, OFPort port, IOFSwitch connectedSwitch,Authenticator authenticator) {
		super(mac, port, connectedSwitch);
		this.authenticator = authenticator;
		isBlocked = true;
		blockedTime = 10;
		authenticator.registerAsMalicious(this);
	}

	@Override
	public void run() {
		while(blockedTime!=0) {
			if(isBlocked) {
				try {
					Thread.sleep(1000);
				}catch(Exception e) {
					
				}
				blockedTime--;
			}else break;
		}
		remove();
	}
	public boolean isBlocked() {
		return isBlocked;
	}
	public void setBlockTime(int blockTime) {
		this.blockedTime = blockTime;
	}
	public int getBlockTime() {
		return this.blockedTime;
	}
	public void register() {
		authenticator.registerAsMalicious(this);
		isBlocked = true;
	}
	public void remove() {
		authenticator.removeAsMalicious(this);
		isBlocked = false;
		blockedTime = defaultBlockTime;
	}

}
