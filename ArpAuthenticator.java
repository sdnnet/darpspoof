package net.floodlightcontroller.sdn_arp_spoof_detection;

import java.util.Collection;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.OFPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.DHCP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;

import java.util.HashMap;
import java.util.HashSet;

import net.floodlightcontroller.dhcpserver.*;
public class ArpAuthenticator implements IFloodlightModule, IOFMessageListener {
	protected static Logger log = LoggerFactory.getLogger(ArpAuthenticator.class);
	protected IFloodlightProviderService floodlightProviderService;
	protected HashMap<IOFSwitch,HashMap<OFPort,IPv4Address>> ipPortMap;
	protected HashMap<IPv4Address,IOFSwitch> ipSwitchMap;
	protected HashSet<SwitchPortPair> blockedSet;
	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return "SDN ARP detector";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}
	protected Command handlePacketInMessage(IOFSwitch sw,OFPacketIn pi,FloodlightContext cntx){
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort()
				: pi.getMatch().get(MatchField.IN_PORT));
		HashMap<OFPort,IPv4Address> actMap = ipPortMap.get(sw);
		if(actMap == null){
			actMap = new HashMap<>();
			ipPortMap.put(sw,actMap); } if(eth.getEtherType().equals(EthType.ARP)){
			ARP arp = (ARP) eth.getPayload();
			IPv4Address addr = arp.getSenderProtocolAddress();
			IOFSwitch actSwitch = ipSwitchMap.get(addr);

			if(actSwitch == null){
				ipSwitchMap.put(addr,sw);
				actSwitch = sw;
				actMap.put(inPort,addr);
			}else{
				if(actSwitch != sw) return Command.CONTINUE;
				IPv4Address realAddr = actMap.get(inPort);
				if(!realAddr.equals(addr)){
					block(inPort,sw);
					return Command.STOP;
				}
			}
		} else if(DHCPServerUtils.isDHCPPacketIn(eth)){
			DHCP payload = DHCPServerUtils.getDHCPayload(eth);
			if(DHCPServerUtils.getMessageType(payload).equals(IDHCPService.MessageType.DISCOVER)){
				IPv4Address addr = actMap.get(inPort);
				if(addr!=null){
					unblockIfMalicious(ipSwitchMap.get(addr),inPort);
					ipSwitchMap.remove(addr);
					actMap.remove(inPort);
				}
			}else if(DHCPServerUtils.getMessageType(payload).equals(IDHCPService.MessageType.REQUEST)){
				IPv4Address addr = payload.getClientIPAddress();
				if(!ipSwitchMap.containsKey(addr)){
					ipSwitchMap.put(addr,sw);
					actMap.put(inPort,addr);
				}
			}else{
			}
		}else{
			if(eth.getEtherType().equals(EthType.IPv4)){
				IPv4 ip = (IPv4) eth.getPayload();
				IPv4Address addr = ip.getSourceAddress();
				IOFSwitch actSwitch = ipSwitchMap.get(addr);
				if(actSwitch == null){
					ipSwitchMap.put(addr,sw);
					actSwitch = sw;
					actMap.put(inPort,addr);
				}else{
					if(actSwitch != sw) return Command.CONTINUE;
					IPv4Address realAddr = actMap.get(inPort);
					if(!realAddr.equals(addr)){
						block(inPort,sw);
						return Command.STOP;
					}
				}
			}
		}
		return Command.CONTINUE;
	}
	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		// TODO Auto-generated method stub
		if(msg.getType().equals(OFType.PACKET_IN)) return handlePacketInMessage(sw,(OFPacketIn) msg,cntx);
		return Command.CONTINUE;
	}

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
		ipPortMap = new HashMap<>();
		ipSwitchMap = new HashMap<>();
		blockedSet = new HashSet<>();
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProviderService.addOFMessageListener(OFType.PACKET_IN, this);

	}
}
