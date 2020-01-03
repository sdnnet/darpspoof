package net.floodlightcontroller.sdn_arp_spoof_detection;


import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;

import net.floodlightcontroller.sdn_arp_spoof_detection.web.ArpJsonMap;

public class ArpEntryResource extends ServerResource{
	@Get("json")
	public ArpJsonMap retrieve(){
		IArpAuthenticatorService ser = (IArpAuthenticatorService) getContext().getAttributes().get(IArpAuthenticatorService.class.getCanonicalName());
		return new ArpJsonMap(ser.getArpMap());
	}
}
