package net.floodlightcontroller.sdn_arp_spoof_detection;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.Masked;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.OFVlanVidMatch;
import org.projectfloodlight.openflow.types.TableId;
import org.projectfloodlight.openflow.types.U64;
import org.projectfloodlight.openflow.types.VlanVid;
import org.python.google.common.collect.ImmutableList;
import org.slf4j.Logger;

import com.google.common.collect.Maps;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IListener.Command;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.types.NodePortTuple;
import net.floodlightcontroller.core.util.AppCookie;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryListener;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.IRoutingDecisionChangedListener;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.routing.Path;
import net.floodlightcontroller.util.OFMessageDamper;

public class ArpForwarding implements IRoutingDecisionChangedListener, ILinkDiscoveryListener {
	protected int FLOWMOD_DEFAULT_PRIORITY = 30;
	protected int FLOWMOD_DEFAULT_HARD_TIMEOUT = 0;
	protected int FLOWMOD_DEFAULT_IDLE_TIMEOUT = 10;
	protected Logger log;
	protected OFMessageDamper messageDamper;
	private IRoutingService routingService;
	private	ILinkDiscoveryService linkService;
	private	TableId DEFAULT_TABLE_ID = TableId.of(2);
	private static final short DECISION_BITS = 24;
	private static final short DECISION_SHIFT = 0;
	private static final long DECISION_MASK = ((1L << DECISION_BITS) - 1) << DECISION_SHIFT;
	private IOFSwitchService switchService;
	private static final short FLOWSET_BITS = 28;
	protected static final short FLOWSET_SHIFT = DECISION_BITS;
	private static final long FLOWSET_MASK = ((1L << FLOWSET_BITS) - 1) << FLOWSET_SHIFT;
	private static final long FLOWSET_MAX = (long) (Math.pow(2, FLOWSET_BITS) - 1);
	public static int ARP_APP_ID = 7;
	static {
		AppCookie.registerApp(ARP_APP_ID, "ArpAuthenticator");
	}
	protected static final U64 ARP_FORWARDING_COOKIE = AppCookie.makeCookie(ARP_APP_ID, 0);
	protected static class FlowSetIdRegistry{
		private volatile Map<NodePortTuple, Set<U64>> nptToFlowSetIds;
		private volatile Map<U64, Set<NodePortTuple>> flowSetIdToNpts;

		private volatile long flowSetGenerator = -1;

		private static volatile FlowSetIdRegistry instance;

		private FlowSetIdRegistry() {
			nptToFlowSetIds = new ConcurrentHashMap<>();
			flowSetIdToNpts = new ConcurrentHashMap<>();
		}

		protected static FlowSetIdRegistry getInstance() {
			if (instance == null) {
				instance = new FlowSetIdRegistry();
			}
			return instance;
		}

		/**
		 * Only for use by unit test to help w/ordering
		 * @param seed
		 */
		protected void seedFlowSetIdForUnitTest(int seed) {
			flowSetGenerator = seed;
		}

		protected synchronized U64 generateFlowSetId() {
			flowSetGenerator += 1;
			if (flowSetGenerator == FLOWSET_MAX) {
				flowSetGenerator = 0;
				log.warn("Flowset IDs have exceeded capacity of {}. Flowset ID generator resetting back to 0", FLOWSET_MAX);
			}
			U64 id = U64.of(flowSetGenerator << FLOWSET_SHIFT);
			//log.debug("Generating flowset ID {}, shifted {}", flowSetGenerator, id);
			return id;
		}

		private void registerFlowSetId(NodePortTuple npt, U64 flowSetId) {
			if (nptToFlowSetIds.containsKey(npt)) {
				Set<U64> ids = nptToFlowSetIds.get(npt);
				ids.add(flowSetId);
			} else {
				Set<U64> ids = new HashSet<>();
				ids.add(flowSetId);
				nptToFlowSetIds.put(npt, ids);
			}  

			if (flowSetIdToNpts.containsKey(flowSetId)) {
				Set<NodePortTuple> npts = flowSetIdToNpts.get(flowSetId);
				npts.add(npt);
			} else {
				Set<NodePortTuple> npts = new HashSet<>();
				npts.add(npt);
				flowSetIdToNpts.put(flowSetId, npts);
			}
		}

		private Set<U64> getFlowSetIds(NodePortTuple npt) {
			return nptToFlowSetIds.get(npt);
		}

		private Set<NodePortTuple> getNodePortTuples(U64 flowSetId) {
			return flowSetIdToNpts.get(flowSetId);
		}

		private void removeNodePortTuple(NodePortTuple npt) {
			nptToFlowSetIds.remove(npt);

			Iterator<Set<NodePortTuple>> itr = flowSetIdToNpts.values().iterator();
			while (itr.hasNext()) {
				Set<NodePortTuple> npts = itr.next();
				npts.remove(npt);
			}
		}

		private void removeExpiredFlowSetId(U64 flowSetId, NodePortTuple avoid, Iterator<U64> avoidItr) {
			flowSetIdToNpts.remove(flowSetId);

			Iterator<Entry<NodePortTuple, Set<U64>>> itr = nptToFlowSetIds.entrySet().iterator();
			boolean removed = false;
			while (itr.hasNext()) {
				Entry<NodePortTuple, Set<U64>> e = itr.next();
				if (e.getKey().equals(avoid) && ! removed) {
					avoidItr.remove();
					removed = true;
				} else {
					Set<U64> ids = e.getValue();
					ids.remove(flowSetId);
				}
			}
		}
	}

	protected FlowSetIdRegistry flowRegistry;
	public ArpForwarding(FloodlightModuleContext context,IOFSwitchService switchService,Logger logger){
		routingService = context.getServiceImpl(IRoutingService.class);
		linkService = context.getServiceImpl(ILinkDiscoveryService.class);
		routingService.addRoutingDecisionChangedListener(this);
		linkService.addListener(this);
		this.switchService = switchService;
		this.log = logger;
	}
	private Set<OFMessage> buildDeleteFlows(OFPort port, Set<OFMessage> msgs, IOFSwitch sw, U64 cookie, U64 cookieMask) {
		if(sw.getOFFactory().getVersion().compareTo(OFVersion.OF_10) == 0) {
			msgs.add(sw.getOFFactory().buildFlowDelete()
					.setCookie(cookie)
					.setTableId(DEFAULT_TABLE_ID)
					// cookie mask not supported in OpenFlow 1.0
					.setMatch(sw.getOFFactory().buildMatch()
						.setExact(MatchField.IN_PORT, port)
						.build())
					.build());

			msgs.add(sw.getOFFactory().buildFlowDelete()
					.setCookie(cookie)
					.setTableId(DEFAULT_TABLE_ID)
					// cookie mask not supported in OpenFlow 1.0
					.setOutPort(port)
					.build());
		}
		else {
			msgs.add(sw.getOFFactory().buildFlowDelete()
					.setCookie(cookie)
					.setCookieMask(cookieMask)
					.setTableId(DEFAULT_TABLE_ID)
					.setMatch(sw.getOFFactory().buildMatch()
						.setExact(MatchField.IN_PORT, port)
						.build())
					.build());

			msgs.add(sw.getOFFactory().buildFlowDelete()
					.setCookie(cookie)
					.setCookieMask(cookieMask)
					.setTableId(DEFAULT_TABLE_ID)
					.setOutPort(port)
					.build());
		}

		return msgs;

	}

	@Override
	public void linkDiscoveryUpdate(List<LDUpdate> updateList) {
		for(LDUpdate update : updateList){
			if(update!=null && (update.getOperation() == UpdateOperation.LINK_REMOVED || update.getOperation() == UpdateOperation.TUNNEL_PORT_REMOVED || update.getOperation() == UpdateOperation.PORT_DOWN)){
				Set<OFMessage> msgs = new HashSet<OFMessage>();
				//for source switch
				if(update.getSrc() != null && !(update.getSrc().equals(DatapathId.NONE))){
					IOFSwitch srcSwitch = switchService.getSwitch(update.getSrc());
					if(srcSwitch != null){
						Set<U64> ids = flowRegistry.getFlowSetIds(new NodePortTuple(update.getSrc(),update.getSrcPort()));
						if(ids != null){
							Iterator<U64> itr = ids.iterator();
							while(itr.hasNext()){
								U64 id = itr.next();
								U64 cookie = id.or(ARP_FORWARDING_COOKIE);
								U64 cookieMask = U64.of(FLOWSET_MASK).or(AppCookie.getAppFieldMask());
								/*delete any flow that matches this or forward to this port*/
								msgs = buildDeleteFlows(update.getSrcPort(),msgs,srcSwitch,cookie,cookieMask);
								messageDamper.write(srcSwitch,msgs);
								Set<NodePortTuple> npts = flowRegistry.getNodePortTuples(id);
								if(npts!=null){
									for(NodePortTuple tpls : npts){
										msgs.clear();
										IOFSwitch sw = switchService.getSwitch(tpls.getNodeId());
										if(sw != null){
											msgs = buildDeleteFlows(tpls.getPortId(),msgs,sw,cookie,cookieMask);
											messageDamper.write(sw,msgs);
										}
									}
								}
								flowRegistry.removeExpiredFlowSetId(id,new NodePortTuple(update.getSrc(),update.getSrcPort()),itr);
							}
						}
					}
					flowRegistry.removeNodePortTuple(new NodePortTuple(update.getSrc(),update.getSrcPort()));
				}
				msgs.clear();
				if(update.getDst() !=null && !(update.getDst().equals(DatapathId.NONE))){
					IOFSwitch dstSwitch = switchService.getSwitch(update.getDst());
					if(dstSwitch!=null){
						Set<U64> ids = flowRegistry.getFlowSetIds(new NodePortTuple(update.getDst(),update.getDstPort()));
						if(ids!=null){
							Iterator<U64> itr = ids.iterator();
							while(itr.hasNext()){
								U64 id = itr.next();
								U64 cookie = id.or(ARP_FORWARDING_COOKIE);
								U64 cookieMask = U64.of(FLOWSET_MASK).or(AppCookie.getAppFieldMask());

								msgs = buildDeleteFlows(update.getDstPort(),msgs,dstSwitch,cookie,cookieMask);
								messageDamper.write(dstSwitch,msgs);
								Set<NodePortTuple> npts = flowRegistry.getNodePortTuples(id);
								if(npts!=null){
									for(NodePortTuple tpls : npts){
										msgs.clear();
										IOFSwitch sw = switchService.getSwitch(tpls.getNodeId());
										if(sw!=null){
											msgs = buildDeleteFlows(tpls.getPortId(),msgs,sw,cookie,cookieMask);
											messageDamper.write(sw,msgs);
										}
									}
								}
								flowRegistry.removeExpiredFlowSetId(id,new NodePortTuple(update.getDst(),update.getDstPort()),itr);
							}
						}
					}
					flowRegistry.removeNodePortTuple(new NodePortTuple(update.getDst(),update.getDstPort()));
				}
			}
		}
	}

	@Override
	public void routingDecisionChanged(Iterable<Masked<U64>> changedDecisions) {
		deleteFlowsByDescriptor(changedDecisions);
	}

	/**
	 * Delete all flows provided by routing decision 
	 * in masked form in all active switches.
	 *
	 * @param descriptors The descriptors and masks which flows to delete.
	 */
	protected void deleteFlowsByDescriptor(Iterable<Masked<U64>> descriptors){
		Collection<Masked<U64>> masked_cookies = convertRoutingDecisionDescriptors(descriptors);
		if(masked_cookies != null && !masked_cookies.isEmpty()){
			Map<OFVersion, List<OFMessage>> cache = Maps.newHashMap();

			for (DatapathId dpid : switchService.getAllSwitchDpids()) {
				IOFSwitch sw = switchService.getActiveSwitch(dpid);
				if (sw == null) {
					continue;
				}

				OFVersion ver = sw.getOFFactory().getVersion();
				if (cache.containsKey(ver)) {
					sw.write(cache.get(ver));
				} else {
					ImmutableList.Builder<OFMessage> msgsBuilder = ImmutableList.builder();
					for (Masked<U64> masked_cookie : masked_cookies) {
						// Consider OpenFlow version when using cookieMask property
						if (ver.compareTo(OFVersion.OF_10) == 0) {
							msgsBuilder.add(
									sw.getOFFactory().buildFlowDelete()
									.setCookie(masked_cookie.getValue())
									// maskCookie not support in OpenFlow 1.0
									.build()
								       );
						}
						else {
							msgsBuilder.add(
									sw.getOFFactory().buildFlowDelete()
									.setCookie(masked_cookie.getValue())
									.setCookieMask(masked_cookie.getMask())
									.build()
								       );
						}

					}

					List<OFMessage> msgs = msgsBuilder.build();
					sw.write(msgs);
					cache.put(ver, msgs);
				}
			}
		}
	}

	protected Collection<Masked<U64>> convertRoutingDecisionDescriptors(Iterable<Masked<U64>> maskedDescriptors) {
		if (maskedDescriptors == null) {
			return null;
		}

		ImmutableList.Builder<Masked<U64>> resultBuilder = ImmutableList.builder();
		for (Masked<U64> maskedDescriptor : maskedDescriptors) {
			long user_mask = AppCookie.extractUser(maskedDescriptor.getMask()) & DECISION_MASK;
			long user_value = AppCookie.extractUser(maskedDescriptor.getValue()) & user_mask;

			resultBuilder.add(
					Masked.of(
						AppCookie.makeCookie(ARP_APP_ID, user_value),
						AppCookie.getAppFieldMask().or(U64.of(user_mask))
						)
					);
		}

		return resultBuilder.build();
	}

	protected Command processPacketInMessage(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx, PortIPTable portIpMap){
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		VlanVid vid = VlanVid.ofVlan(eth.getVlanID());
		if(eth.getEtherType().equals(EthType.ARP)){
			ARP arp = (ARP) eth.getPayload();
			NodePortTuple destTuple = portIpMap.getSwitchFor(vid,arp.getTargetProtocolAddress());
			if(destTuple == null) return Command.STOP;
			NodePortTuple srcTuple = portIpMap.getSwitchFor(vid,arp.getSenderProtocolAddress());
			if(srcTuple == null){
				log.info("GOT a malicious packet");
				return Command.STOP;
			}
			IRoutingDecision decision = IRoutingDecision.rtStore.get(cntx, IRoutingDecision.CONTEXT_DECISION);
			U64 flowId = flowRegistry.generateFlowSetId();
			U64 cookie = makeForwardingCookie(decision,flowId);
			Path path = routingService.getPath(srcTuple.getNodeId(),srcTuple.getPortId(),destTuple.getNodeId(),destTuple.getPortId());
			Match match = sw.getOFFactory().buildMatch().setExact(MatchField.ETH_TYPE,EthType.ARP).setExact(MatchField.ARP_TPA,arp.getTargetProtocolAddress()).setExact(MatchField.VLAN_VID,OFVlanVidMatch.ofVlanVid(vid)).build();
			if(path.getPath().isEmpty()){
				return Command.STOP;
			}
			installRoute(match,sw,path,pi,cntx,cookie);
			for(NodePortTuple npt : path.getPath()){
				flowRegistry.registerFlowSetId(npt,flowId);
			}
		}
		return Command.CONTINUE;
	}

	private boolean installRoute(Match match,IOFSwitch initSwitch,Path path,OFPacketIn pi,FloodlightContext cntx,U64 cookie){
		List<NodePortTuple> paths = path.getPath();
		for(int indx = paths.size()-1; indx>0; indx-=2){
			DatapathId dpid = paths.get(indx).getNodeId();
			IOFSwitch sw = switchService.getSwitch(dpid);
			if(sw == null){
				log.warn("Cannot install route because switch with dpid {} is missing",dpid);
				return false;
			}
			OFFactory factory = sw.getOFFactory();
			OFPort outPort = paths.get(indx).getPortId();
			ArrayList<OFAction> list = new ArrayList<>();
			list.add(factory.actions().buildOutput().setPort(outPort).build());
			OFFlowAdd flowAdd = factory.buildFlowAdd().setTableId(DEFAULT_TABLE_ID).setMatch(match).setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT).setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT).setCookie(cookie).setActions(list).setBufferId(OFBufferId.NO_BUFFER).build();
			sw.write(flowAdd);
		}
		return true;
	}
	protected U64 makeForwardingCookie(IRoutingDecision decision, U64 flowSetId) {
		long user_fields = 0;

		U64 decision_cookie = (decision == null) ? null : decision.getDescriptor();
		if (decision_cookie != null) {
			user_fields |= AppCookie.extractUser(decision_cookie) & DECISION_MASK;
		}

		if (flowSetId != null) {
			user_fields |= AppCookie.extractUser(flowSetId) & FLOWSET_MASK;
		}

		// TODO: Mask in any other required fields here

		if (user_fields == 0) {
			return ARP_FORWARDING_COOKIE;
		}
		return AppCookie.makeCookie(ARP_APP_ID, user_fields);
	}
}
