package net.floodlightcontroller.sdn_arp_spoof_detection;

import net.floodlightcontroller.core.IOFMessageListener;

public interface Authenticator extends  IOFMessageListener{
	void registerUser(User user);
	void removeUser(User user);
	void registerAsMalicious(User user);
	void removeAsMalicious(User user);
	void unblockMaliciousUser(User user);
}
