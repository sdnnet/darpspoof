package net.floodlightcontroller.sdn_arp_spoof_detection;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFFlowDelete;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv4AddressWithMask;
import org.projectfloodlight.openflow.types.MacAddress;
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
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.sdn_arp_spoof_detection.web.*;

import java.util.HashMap;

import net.floodlightcontroller.dhcpserver.*;
public class ArpAuthenticator implements IFloodlightModule, IOFMessageListener ,IArpAuthenticatorService{
	protected ARPDHCP dhcp;
	protected static Logger log = LoggerFactory.getLogger(ArpAuthenticator.class);
	protected IRestApiService restApiService;
	protected IFloodlightProviderService floodlightProviderService;
	protected HashMap<IOFSwitch,HashMap<OFPort,IPMacPair>> switchMap;
	protected HashMap<MacAddress,SwitchPortPair> macMap;
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
	private Match createMatch(IOFSwitch sw,OFPort port){
		OFFactory factory = sw.getOFFactory();
		return factory.buildMatch().setExact(MatchField.IN_PORT,port)
			.setExact(MatchField.ETH_TYPE,EthType.ARP)
			.setMasked(MatchField.ARP_SPA,IPv4AddressWithMask.of("0.0.0.0/0"))
			.build();
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
		OFFlowAdd flow =factory.buildFlowAdd().setMatch(m).setHardTimeout(0).setIdleTimeout(0).setPriority(1000).setActions(actions).build();
		sw.write(flow);
	}
	private void writeUnblockFlow(IOFSwitch sw,Match m){
		OFFactory factory = sw.getOFFactory();
		OFFlowDelete flow =factory.buildFlowDelete().setMatch(m).build();
		sw.write(flow);
	}
	private void unblockIfMalicious(IOFSwitch sw,OFPort port){
		Match m = createMatch(sw,port);
		writeUnblockFlow(sw,m);
	}
	private void block(OFPort port,IOFSwitch sw,IPv4Address addr){
		Match m = createMatch(sw,port,addr);
		writeBlockFlow(m,sw);
	}
	protected Command handlePacketInMessage(IOFSwitch sw,OFPacketIn pi,FloodlightContext cntx){
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort()
				: pi.getMatch().get(MatchField.IN_PORT));
		HashMap<OFPort,IPMacPair> actMap = switchMap.get(sw);
		if(actMap == null){
			actMap = new HashMap<>();
			switchMap.put(sw,actMap); 
		}
		if(eth.getEtherType().equals(EthType.ARP)){
			ARP arp = (ARP) eth.getPayload();
			IPv4Address addr = arp.getSenderProtocolAddress();
			if(addr.equals(IPv4Address.of("0.0.0.0"))) return Command.CONTINUE;
			if(actMap.containsKey(inPort)){
				if(!addr.equals(actMap.get(inPort).getIp())){
					block(inPort,sw,addr);
					return Command.STOP;
				}
			}
		} else if(DHCPServerUtils.isDHCPPacketIn(eth)){
			DHCP payload = DHCPServerUtils.getDHCPayload(eth);
			if(DHCPServerUtils.getMessageType(payload).equals(IDHCPService.MessageType.REQUEST)){
				if(actMap.containsKey(inPort)){
					unblockIfMalicious(sw,inPort);
					macMap.remove(actMap.get(inPort).getMac());
					actMap.remove(inPort);
				}
				if(!macMap.containsKey(eth.getSourceMACAddress())){
					macMap.put(eth.getSourceMACAddress(),new SwitchPortPair(sw,inPort));
				}
			}else if(DHCPServerUtils.getMessageType(payload).equals(IDHCPService.MessageType.ACK)){
				handleDHCPACK(eth,payload);
			}
		}
		return Command.CONTINUE;
	}
	private void handleDHCPACK(Ethernet eth,DHCP payload){
		SwitchPortPair pair = macMap.get(eth.getDestinationMACAddress());
		IPMacPair iPair = new IPMacPair(payload.getYourIPAddress(),eth.getDestinationMACAddress());
		HashMap<OFPort,IPMacPair> innerMap = switchMap.get(pair.getSwitch());
		if(innerMap == null){
			innerMap = new HashMap<>();
			switchMap.put(pair.getSwitch(),innerMap);
		}
		innerMap.put(pair.getPort(),iPair);
	}
	private Command handlePacketOutMessage(IOFSwitch sw,OFPacketOut pi,FloodlightContext cntx){
		Ethernet eth = new Ethernet();
		eth = (Ethernet) eth.deserialize(pi.getData(),0,pi.getData().length);
		if(DHCPServerUtils.isDHCPPacketIn(eth)){
			DHCP payload = DHCPServerUtils.getDHCPayload(eth);
			if(DHCPServerUtils.getMessageType(payload).equals(IDHCPService.MessageType.ACK)){
				handleDHCPACK(eth,payload);
			}
		}
		return Command.CONTINUE;

	}
	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		// TODO Auto-generated method stub
		if(msg.getType().equals(OFType.PACKET_IN)) return handlePacketInMessage(sw,(OFPacketIn) msg,cntx);
		else if(msg.getType().equals(OFType.PACKET_OUT)) return handlePacketOutMessage(sw,(OFPacketOut)msg,cntx);
		return Command.CONTINUE;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		Collection<Class<? extends IFloodlightService>> l  = new ArrayList<>();
		l.add(IArpAuthenticatorService.class);
		return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		Map<Class<? extends IFloodlightService>,IFloodlightService> m  = new HashMap<>();
		m.put(IArpAuthenticatorService.class,this);
		return m;
	}


	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		// TODO Auto-generated method stub
		Collection<Class<? extends IFloodlightService>> l =new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IRestApiService.class);
		l.add(IFloodlightProviderService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProviderService = context.getServiceImpl(IFloodlightProviderService.class);
		restApiService = context.getServiceImpl(IRestApiService.class);
		macMap = new HashMap<>();
		switchMap = new HashMap<>();
		dhcp = new ARPDHCP(context);

	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProviderService.addOFMessageListener(OFType.PACKET_IN, this);
		floodlightProviderService.addOFMessageListener(OFType.PACKET_OUT, this);
		restApiService.addRestletRoutable(new ArpAuthenticatorWebRoutable());
	}

	@Override
	public HashMap<IOFSwitch, HashMap<OFPort, IPMacPair>> getArpMap() {
		// TODO Auto-generated method stub
		return switchMap;
	}

}
