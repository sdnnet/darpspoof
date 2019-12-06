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
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.U64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.packet.Ethernet;

public class MacAuthenticator implements Authenticator<MacAddress> {
	private static final long COOKIE = 135719;
	protected static Logger log = LoggerFactory.getLogger(MacAuthenticator.class);

	protected IFloodlightProviderService floodlightProvider;
	protected HashSet<User<MacAddress>> userRecord;
	protected HashSet<User<MacAddress>> maliciousUsers;
	protected HashMap<IOFSwitch,HashMap<OFPort,MacAddress>> userMap;
	public MacAuthenticator(IFloodlightProviderService service){
		this.floodlightProvider = service;
		userRecord = new HashSet<>();
		userMap = new HashMap<>();
	}
	private Command handlePacketInMessage(IOFSwitch sw,OFPacketIn pi,FloodlightContext cntx){
		OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		MacAddress senderAddress = eth.getSourceMACAddress();
		HashMap<OFPort,MacAddress> record = userMap.get(sw);
		if(record==null){
			userMap.put(sw,new HashMap<>());
			record = userMap.get(sw);
		}
		MacAddress realAddress = record.get(inPort);
		if(realAddress==null){
			User<MacAddress> user = new User<>(senderAddress,inPort,sw);
			this.registerUser(user);
		}
		else if(!realAddress.equals(senderAddress)){
			log.info("Not a legal user");
			this.registerAsMalicious(new User<>(senderAddress,inPort,sw));
		}
		log.info("real address: {}",realAddress);
		log.info("sender address: {}" ,senderAddress);
		return Command.CONTINUE;
	}
	private Command handleFlowRemoved(IOFSwitch sw,OFFlowRemoved msg,FloodlightContext cntx){
		
		OFPort inPort = msg.getMatch().get(MatchField.IN_PORT);
		log.info("FLOW REMOVED MESSAGE FOUND"); 
		if(msg.getCookie().getValue() == COOKIE){
			MacAddress realAddress = userMap.get(sw).get(inPort);
			User<MacAddress> user = new User<>(realAddress,inPort,sw);
			removeAsMalicious(user);
		}else{
			if(msg.getReason().equals(OFFlowRemovedReason.IDLE_TIMEOUT)){
				MacAddress realAddress = userMap.get(sw).get(inPort);
				User<MacAddress> user = new User<>(realAddress,inPort,sw);
				if(maliciousUsers.contains(user)){
					removeAsMalicious(user);
				}
				removeUser(user);
			}
		}
		
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
	public void registerUser(User<MacAddress> user) {
		HashMap<OFPort,MacAddress> record = userMap.get(user.getConnectedSwitch());
		record.put(user.getPort(),user.getAddress());
	}

	@Override
	public void removeUser(User<MacAddress> user) {
		HashMap<OFPort,MacAddress> record = userMap.get(user.getConnectedSwitch());
		record.remove(user.getPort());
		userRecord.remove(user);
	}

	@Override
	public void registerAsMalicious(User<MacAddress> user) {
		maliciousUsers.add(user);	
		Match match = createMatch(user);
		writeBlockFlow(user.getConnectedSwitch(),match);
	}

	@Override
	public void removeAsMalicious(User<MacAddress> user) {
		maliciousUsers.remove(user);
		unblockMaliciousUser(user);
	}

	@Override
	public void unblockMaliciousUser(User<MacAddress> user) {

	}
	private Match createMatch(User<MacAddress> user){
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
	}*/
		
}

