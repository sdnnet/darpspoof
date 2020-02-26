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
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
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
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.PortChangeType;
import net.floodlightcontroller.core.internal.IOFSwitchService;
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
public class ArpAuthenticator implements IFloodlightModule, IOFMessageListener ,IArpAuthenticatorService,IOFSwitchListener{
	protected IOFSwitchService switchService;
	protected static Logger log = LoggerFactory.getLogger(ArpAuthenticator.class);
	protected IRestApiService restApiService;
	protected IFloodlightProviderService floodlightProviderService;
	//For <port-ip> mapping, mac is there for removing mac entry from macMap while unblocking in constant time
	protected HashMap<DatapathId,HashMap<OFPort,IPMacPair>> switchMap;
	//For <mac-<switch-port>> mapping so that we can reach to right switch using DHCPACK
	protected HashMap<MacAddress,SwitchPortPair> macMap;
	protected ARPDHCP dhcp;


	@Override
	public String getName() {
		return "ArpAuthenticator";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return false;
	}

	//This module will get packet before forwarding module
	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return name.equals("forwarding")||name.equals("dhcpserver");
	}


	/* Match used for unblocking purpose
	 * ARP source protocol address is masked
	 * for 0.0.0.0/0 i.e., any IP address
	 * to delete all IP on a given port
	 */
	private Match createMatch(IOFSwitch sw,OFPort port){
		OFFactory factory = sw.getOFFactory();
		return factory.buildMatch().setExact(MatchField.IN_PORT,port)
			.setExact(MatchField.ETH_TYPE,EthType.ARP)
			.setMasked(MatchField.ARP_SPA,IPv4AddressWithMask.of("0.0.0.0/0"))
			.build();
	}



	/* Match used for blocking purpose
	 * To block ip address "addr" on 
	 * OFPort "port"
	 */
	private Match createMatch(IOFSwitch sw,OFPort port,IPv4Address addr){
		OFFactory factory = sw.getOFFactory();
		return factory.buildMatch().setExact(MatchField.IN_PORT,port)
			.setExact(MatchField.ETH_TYPE,EthType.ARP)
			.setExact(MatchField.ARP_SPA,addr)
			.build();
	}




	/* Write block flow for unlimited time
	 * on basis of block match
	 */
	private void writeBlockFlow(Match m,IOFSwitch sw){
		OFFactory factory = sw.getOFFactory();
		ArrayList<OFAction> actions = new ArrayList<>();
		OFFlowAdd flow =factory.buildFlowAdd().setMatch(m).setHardTimeout(0).setIdleTimeout(0).setPriority(1000).setActions(actions).build();
		sw.write(flow);
	}


	/* Write unblock flow i.e., delete block flow
	 * on basis on unblock match
	 */
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

	// handles both ARP and DHCP
	protected Command handlePacketInMessage(IOFSwitch sw,OFPacketIn pi,FloodlightContext cntx){
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort()
				: pi.getMatch().get(MatchField.IN_PORT));
		HashMap<OFPort,IPMacPair> actMap = switchMap.get(sw.getId());
		if(actMap == null){
			actMap = new HashMap<>();
			switchMap.put(sw.getId(),actMap); 
		}
		/* if we get arp from unregistered port of switch
		 * it means that arp is verified by any other switch 
		 * previously so, not checking that case.
		 * (As it will be switch connection link that's why
		 * it is not registered)
		 *
		 * If we get different arp source protocol address
		 * as registered than block that flow
		 */
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
		} 

		/* if we get a dhcp request from a port it means a 
		 * new device is connected to that port.
		 * So, remove any entry from data-structure and 
		 * flow rules from switch for that port(if any)
		 *
		 * if we get a dhcp ack (which can be sent by
		 * any dhcpserver machine or VM as it is a packet
		 * in message) so handle it by registration of
		 * IP address
		 */
		else if(DHCPServerUtils.isDHCPPacketIn(eth)){
			DHCP payload = DHCPServerUtils.getDHCPayload(eth);
			if(DHCPServerUtils.getMessageType(payload).equals(IDHCPService.MessageType.REQUEST)){
				if(actMap.containsKey(inPort)){
					unblockIfMalicious(sw,inPort);
					macMap.remove(actMap.get(inPort).getMac());
					actMap.remove(inPort);
				}
				if(!macMap.containsKey(eth.getSourceMACAddress())){
					log.info("GOT REQUEST: {}",eth.getSourceMACAddress());
					macMap.put(eth.getSourceMACAddress(),new SwitchPortPair(sw.getId(),inPort));
				}
			}else if(DHCPServerUtils.getMessageType(payload).equals(IDHCPService.MessageType.ACK)){
				log.info("GOT ACK: {}",eth.getDestinationMACAddress());
				handleDHCPACK(eth,payload);
			}
		}
		return Command.CONTINUE;
	}



	/* registers the new IP address in switchMap.
	 * It gets the required switch and port for 
	 * registration using macMap.
	 * macMap entry itself was added while handling 
	 * DHCPRequest previously.
	 */
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


	/* handles DHCPACK by controller
	 * as if controller generates ack 
	 * it will be a packet-out message
	 */
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



	/* handles both PacketIn and PacketOut message
	 * as PacketOut message can also have DHCPACK
	 * when controllers act as DHCP server
	 */
	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		if(msg.getType().equals(OFType.PACKET_IN)) return handlePacketInMessage(sw,(OFPacketIn) msg,cntx);
		else if(msg.getType().equals(OFType.PACKET_OUT)) return handlePacketOutMessage(sw,(OFPacketOut)msg,cntx);
		return Command.CONTINUE;
	}



	//Expose REST API service 
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		Collection<Class<? extends IFloodlightService>> l  = new ArrayList<>();
		l.add(IArpAuthenticatorService.class);
		return l;
	}


	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		Map<Class<? extends IFloodlightService>,IFloodlightService> m  = new HashMap<>();
		m.put(IArpAuthenticatorService.class,this);
		return m;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l =new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IRestApiService.class);
		l.add(IFloodlightProviderService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProviderService = context.getServiceImpl(IFloodlightProviderService.class);
		restApiService = context.getServiceImpl(IRestApiService.class);
		switchService = context.getServiceImpl(IOFSwitchService.class);
		macMap = new HashMap<>();
		switchMap = new HashMap<>();
		dhcp = new ARPDHCP(context);
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProviderService.addOFMessageListener(OFType.PACKET_IN, this);
		floodlightProviderService.addOFMessageListener(OFType.PACKET_OUT, this);
		restApiService.addRestletRoutable(new ArpAuthenticatorWebRoutable());
		switchService.addOFSwitchListener(this);
	}

	@Override
	public HashMap<DatapathId, HashMap<OFPort, IPMacPair>> getArpMap() {
		return switchMap;
	}

	@Override
	public void switchAdded(DatapathId switchId) {
		// TODO Auto-generated method stub

	}

	@Override
	public void switchRemoved(DatapathId switchId) {
		// TODO Auto-generated method stub
		switchMap.remove(switchId);
		macMap.entrySet().removeIf(entry->(entry.getValue().getSwitch().equals(switchId)));
	}

	@Override
	public void switchActivated(DatapathId switchId) {
		// TODO Auto-generated method stub

	}

	@Override
	public void switchPortChanged(DatapathId switchId, OFPortDesc port, PortChangeType type) {
		// TODO Auto-generated method stub

	}

	@Override
	public void switchChanged(DatapathId switchId) {
		// TODO Auto-generated method stub

	}

	@Override
	public void switchDeactivated(DatapathId switchId) {
		// TODO Auto-generated method stub

	}

}
