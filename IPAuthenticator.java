package net.floodlightcontroller.sdn_arp_spoof_detection;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFFlowRemoved;
import org.projectfloodlight.openflow.protocol.OFFlowRemovedReason;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActions;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.ArpOpcode;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPAddress;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.U64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IListener.Command;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;

public class IPAuthenticator implements Authenticator<IPv4Address> {
	private static final long COOKIE = 135719;
	protected static Logger log = LoggerFactory.getLogger(IPAuthenticator.class);

	protected IFloodlightProviderService floodlightProvider;
	protected HashSet<User<IPv4Address>> userRecord;
	protected HashSet<User<IPv4Address>> maliciousUsers;
	protected HashMap<IOFSwitch,HashMap<OFPort,IPv4Address>> userMap;
	public IPAuthenticator(IFloodlightProviderService service){
		this.floodlightProvider = service;
		userRecord = new HashSet<>();
		userMap = new HashMap<>();
		maliciousUsers =  new HashSet<>();
	}
	private Command handlePacketInMessage(IOFSwitch sw,OFPacketIn pi,FloodlightContext cntx){
		OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		EthType etherType = eth.getEtherType();
		if(etherType.equals(EthType.ARP)){
			HashMap<OFPort,IPv4Address> record = userMap.get(sw);
			IPv4Address senderAddress = ((ARP)eth.getPayload()).getSenderProtocolAddress();
			if(record==null){
				userMap.put(sw,new HashMap<>());
				record = userMap.get(sw);
			}
			IPv4Address realAddress = record.get(inPort);
			if(realAddress==null){
				User<IPv4Address> user = new User<>(senderAddress,inPort,sw);
				this.registerUser(user);
			}
			else if(!realAddress.equals(senderAddress)){
				log.info("Not a legal user");
				this.registerAsMalicious(new User<>(senderAddress,inPort,sw));
				return Command.STOP;
			}
			log.info("real address: {}",realAddress);
			log.info("sender address: {}" ,senderAddress);
		}else if(etherType.equals(EthType.IPv4)){
			HashMap<OFPort,IPv4Address> record = userMap.get(sw);
			IPv4Address senderAddress = ((IPv4)eth.getPayload()).getSourceAddress();
			if(record==null){
				userMap.put(sw,new HashMap<>());
				record = userMap.get(sw);
			}
			IPv4Address realAddress = record.get(inPort);
			if(realAddress==null){
				User<IPv4Address> user = new User<>(senderAddress,inPort,sw);
				this.registerUser(user);
			}
			else if(!realAddress.equals(senderAddress)){
				log.info("Not a legal user");
				this.registerAsMalicious(new User<>(senderAddress,inPort,sw));
				return Command.STOP;
			}
			log.info("real address: {}",realAddress);
			log.info("sender address: {}" ,senderAddress);
		}
		return Command.CONTINUE;
	}
	private Command handleFlowRemoved(IOFSwitch sw,OFFlowRemoved msg,FloodlightContext cntx){
		/*
		OFPort inPort = msg.getMatch().get(MatchField.IN_PORT);
		log.info("FLOW REMOVED MESSAGE FOUND"); 
		if(msg.getCookie().getValue() == COOKIE){
			MacAddress realAddress = userMap.get(sw).get(inPort);
			User user = new User(realAddress,inPort,sw);
			removeAsMalicious(user);
		}else{
			if(msg.getReason().equals(OFFlowRemovedReason.IDLE_TIMEOUT)){
				MacAddress realAddress = userMap.get(sw).get(inPort);
				User user = new User(realAddress,inPort,sw);
				if(maliciousUsers.contains(user)){
					removeAsMalicious(user);
				}
				removeUser(user);
			}
		}
		*/
		return Command.CONTINUE;
	}
	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		log.info("GOT A PACKET");
		OFType type = msg.getType();
		if(type.equals(OFType.PACKET_IN)){
			return handlePacketInMessage(sw,(OFPacketIn)msg,cntx);
		}else if(type.equals(OFType.FLOW_REMOVED)){
			return handleFlowRemoved(sw,(OFFlowRemoved)msg,cntx);
		}else{
			log.info("Recieved wrong packet");
			return Command.CONTINUE;
		}
	}

	@Override
	public String getName() {
		return "Authenticator";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return name.equals("Learning Switch");
	}

	@Override
	public void registerUser(User<IPv4Address> user) {
		HashMap<OFPort,IPv4Address> record = userMap.get(user.getConnectedSwitch());
		record.put(user.getPort(),user.getAddress());
	}

	@Override
	public void removeUser(User<IPv4Address> user) {
		HashMap<OFPort,IPv4Address> record = userMap.get(user.getConnectedSwitch());
		record.remove(user.getPort());
		userRecord.remove(user);
	}

	@Override
	public void registerAsMalicious(User<IPv4Address> user) {
		maliciousUsers.add(user);	
		Match match = createMatch(user);
		writeBlockFlow(user.getConnectedSwitch(),match);
	}

	@Override
	public void removeAsMalicious(User<IPv4Address> user) {
		maliciousUsers.remove(user);
		unblockMaliciousUser(user);
	}

	@Override
	public void unblockMaliciousUser(User<IPv4Address> user) {

	}
	private Match createMatch(User<IPv4Address> user){
		IOFSwitch sw = user.getConnectedSwitch();
		OFFactory factory = sw.getOFFactory();
		return factory.buildMatch().setExact(MatchField.IN_PORT,user.getPort()).build();
	}
	private void writeBlockFlow(IOFSwitch sw,Match match){
		List<OFAction> actionList = new ArrayList<>();
		OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowAdd()
		.setMatch(match)
		.setCookie(U64.of(COOKIE))
		.setIdleTimeout(10)
		.setHardTimeout(10)
		.setPriority(20000)
		.setBufferId(OFBufferId.NO_BUFFER)
		.setActions(actionList)
		.setPriority(3);
		sw.write(fmb.build());
	}
	/*
	private Match createArpMatch(IOFSwitch sw){
		OFFactory factory = sw.getOFFactory();
		return factory.buildMatch().setExact(MatchField.ETH_DST,MacAddress.BROADCAST)
			.setExact(MatchField.ETH_TYPE,EthType.ARP)
			.setExact(MatchField.ARP_OP,ArpOpcode.REQUEST)
			.build();
	}
	private void writeArpFlow(IOFSwitch sw,Match match){
		OFActions actions = sw.getOFFactory().actions();
		List<OFAction> actionList = new ArrayList<>();
		OFAction controllerAction = actions.buildOutput().setPort(OFPort.CONTROLLER).setMaxLen(10000).build();
		OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowAdd();
		fmb.setMatch(match);
		fmb.setCookie(U64.of(COOKIE));
		fmb.setIdleTimeout(0);
		fmb.setHardTimeout(0);
		fmb.setPriority(20000);
		fmb.setBufferId(OFBufferId.NO_BUFFER);
		fmb.setActions(actionList);
		sw.write(fmb.build());
	}
	*/	
}

