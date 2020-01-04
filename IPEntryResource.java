package net.floodlightcontroller.sdn_arp_spoof_detection;


import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;

import net.floodlightcontroller.sdn_arp_spoof_detection.web.IPJsonMap;

public class IPEntryResource extends ServerResource{
	@Get("json")
	public IPJsonMap retrieve(){
		IArpAuthenticatorService ser = (IArpAuthenticatorService) getContext().getAttributes().get(IArpAuthenticatorService.class.getCanonicalName());
		return new IPJsonMap(ser.getIPMap());
	}
}
