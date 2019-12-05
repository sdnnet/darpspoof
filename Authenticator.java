package net.floodlightcontroller.sdn_arp_spoof_detection;

import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitchListener;

public interface Authenticator<T> extends  IOFMessageListener{
	void registerUser(User<T> user);
	void removeUser(User<T> user);
	void registerAsMalicious(User<T> user);
	void removeAsMalicious(User<T> user);
	void unblockMaliciousUser(User<T> user);
}
