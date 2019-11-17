package net.floodlightcontroller.arp_detect;

import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitchListener;

public interface Authenticator extends IOFSwitchListener , IOFMessageListener{
	void registerUser(User user);
	void removeUser(User user);
	void registerAsMalicious(User user);
	void removeAsMalicious(User user);
	void unblockMaliciousUser(MaliciousUser user);
}
