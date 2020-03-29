package net.floodlightcontroller.sdn_arp_spoof_detection;

import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.Masked;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TableId;
import org.projectfloodlight.openflow.types.U64;
import org.python.google.common.collect.ImmutableList;

import com.google.common.collect.Maps;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.types.NodePortTuple;
import net.floodlightcontroller.core.util.AppCookie;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryListener;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.routing.IRoutingDecisionChangedListener;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.util.OFMessageDamper;

public class ArpForwarding implements IRoutingDecisionChangedListener, ILinkDiscoveryListener {
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
				//log.warn("Flowset IDs have exceeded capacity of {}. Flowset ID generator resetting back to 0", FLOWSET_MAX);
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
	public ArpForwarding(FloodlightModuleContext context,IOFSwitchService switchService){
		routingService = context.getServiceImpl(IRoutingService.class);
		linkService = context.getServiceImpl(ILinkDiscoveryService.class);
		routingService.addRoutingDecisionChangedListener(this);
		linkService.addListener(this);
		this.switchService = switchService;
	}
	private Set<OFMessage> buildDeleteFlows(OFPort port, Set<OFMessage> msgs, IOFSwitch sw, U64 cookie, U64 cookieMask) {
		if(sw.getOFFactory().getVersion().compareTo(OFVersion.OF_10) == 0) {
			msgs.add(sw.getOFFactory().buildFlowDelete()
					.setCookie(cookie)
					// cookie mask not supported in OpenFlow 1.0
					.setMatch(sw.getOFFactory().buildMatch()
						.setExact(MatchField.IN_PORT, port)
						.build())
					.build());

			msgs.add(sw.getOFFactory().buildFlowDelete()
					.setCookie(cookie)
					// cookie mask not supported in OpenFlow 1.0
					.setOutPort(port)
					.build());
		}
		else {
			msgs.add(sw.getOFFactory().buildFlowDelete()
					.setCookie(cookie)
					.setCookieMask(cookieMask)
					.setMatch(sw.getOFFactory().buildMatch()
						.setExact(MatchField.IN_PORT, port)
						.build())
					.build());

			msgs.add(sw.getOFFactory().buildFlowDelete()
					.setCookie(cookie)
					.setCookieMask(cookieMask)
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

}
