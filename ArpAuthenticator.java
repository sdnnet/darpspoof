package net.floodlightcontroller.sdn_arp_spoof_detection;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFFlowDelete;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
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

import java.util.HashMap;

import net.floodlightcontroller.dhcpserver.*;
public class ArpAuthenticator implements IFloodlightModule, IOFMessageListener {
	protected static Logger log = LoggerFactory.getLogger(ArpAuthenticator.class);
	protected IFloodlightProviderService floodlightProviderService;
	protected HashMap<IOFSwitch,HashMap<OFPort,IPv4Address>> ipPortMap;
	protected HashMap<IPv4Address,IOFSwitch> ipSwitchMap;
	protected HashMap<IOFSwitch,HashMap<OFPort,ArrayList<IPv4Address>>> blockedMap;
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
	private Match createMatch(IOFSwitch sw,OFPort port,IPv4Address addr){
		OFFactory factory = sw.getOFFactory();
		return factory.buildMatch().setExact(MatchField.IN_PORT,port)
			.setExact(MatchField.ETH_TYPE,EthType.ARP)
			.setExact(MatchField.ARP_SPA,addr)
			.build();
	}
	private void writeBlockFlow(Match m,IOFSwitch sw){
		OFFactory factory = sw.getOFFactory();
		ArrayList<OFAction> actions = new ArrayList<>();
		OFFlowAdd flow =factory.buildFlowAdd().setMatch(m).setHardTimeout(0).setIdleTimeout(0).setActions(actions).build();
		sw.write(flow);
	}
	private void writeUnblockFlow(IOFSwitch sw,Match m){
		OFFactory factory = sw.getOFFactory();
		OFFlowDelete flow =factory.buildFlowDelete().setMatch(m).build();
		sw.write(flow);
	}
	private void unblockIfMalicious(IOFSwitch sw,OFPort port){
		HashMap<OFPort,ArrayList<IPv4Address>> switchMap = blockedMap.get(sw);
		if(switchMap == null) return;
		ArrayList<IPv4Address> blockList = switchMap.get(port);
		if(blockList == null) return;
		for(IPv4Address addr : blockList){
			Match m = createMatch(sw,port,addr);
			writeUnblockFlow(sw,m);
		}
		blockList.clear();
	}
	private void block(OFPort port,IOFSwitch sw,IPv4Address addr){
		HashMap<OFPort,ArrayList<IPv4Address>> switchMap = blockedMap.get(sw);
		if(switchMap == null) {
			switchMap = new HashMap<>();
			blockedMap.put(sw,switchMap);
		}
		ArrayList<IPv4Address> blockList = switchMap.get(port);
		if(blockList == null){
			blockList = new ArrayList<>();
			switchMap.put(port,blockList);
		}
		blockList.add(addr);
		Match m = createMatch(sw,port,addr);
		writeBlockFlow(m,sw);
	}
	protected Command handlePacketInMessage(IOFSwitch sw,OFPacketIn pi,FloodlightContext cntx){
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort()
				: pi.getMatch().get(MatchField.IN_PORT));
		HashMap<OFPort,IPv4Address> actMap = ipPortMap.get(sw);
		if(actMap == null){
			actMap = new HashMap<>();
			ipPortMap.put(sw,actMap); 
		}
		if(eth.getEtherType().equals(EthType.ARP)){
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
					block(inPort,sw,addr);
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
		blockedMap = new HashMap<>();
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProviderService.addOFMessageListener(OFType.PACKET_IN, this);

	}
}
