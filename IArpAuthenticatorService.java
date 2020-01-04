package net.floodlightcontroller.sdn_arp_spoof_detection;

import java.util.HashMap;

import org.projectfloodlight.openflow.types.OFPort;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.IFloodlightService;

public interface IArpAuthenticatorService extends IFloodlightService{
	public HashMap<IOFSwitch,HashMap<OFPort,IPMacPair>> getArpMap();
}
