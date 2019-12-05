package net.floodlightcontroller.sdn_arp_spoof_detection;

import java.util.Collection;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;

public class ArpSpoofDetector implements IFloodlightModule {
	protected static Logger log = LoggerFactory.getLogger(ArpSpoofDetector.class);
	protected IFloodlightProviderService floodlightProviderService;
	protected IOFSwitchService switchService;
	private Authenticator<IPv4Address> authenticator;
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;

	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProviderService = context.getServiceImpl(IFloodlightProviderService.class);
		switchService = context.getServiceImpl(IOFSwitchService.class);
		authenticator = new IPAuthenticator(floodlightProviderService);
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProviderService.addOFMessageListener(OFType.PACKET_IN, authenticator);
		floodlightProviderService.addOFMessageListener(OFType.FLOW_REMOVED, authenticator);
	}

}