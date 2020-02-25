package net.floodlightcontroller.sdn_arp_spoof_detection;

import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.dhcpserver.DHCPInstance;
import net.floodlightcontroller.dhcpserver.DHCPInstance.DHCPInstanceBuilder;
import net.floodlightcontroller.dhcpserver.IDHCPService;

import java.util.ArrayList;
import java.util.HashSet;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.VlanVid;
public class ARPDHCP {
	private IDHCPService service;
	private DHCPInstance dList;
	public ARPDHCP(FloodlightModuleContext context){
		service = context.getServiceImpl(IDHCPService.class);
		buildDHCP();
		service.addInstance(dList);
	}
	private void buildDHCP(){
		HashSet<VlanVid> set = new HashSet<VlanVid>();
		set.add(VlanVid.ofVlan(0));
		set.add(VlanVid.ofVlan(1));
		DHCPInstanceBuilder builder = new DHCPInstanceBuilder("vlan0").setEndIP(IPv4Address.of("10.0.0.254"))
			.setLeaseTimeSec(200)
			.setDNSServers(new ArrayList<>())
			.setNTPServers(new ArrayList<>())
			.setIPforwarding(true)
			.setStartIP(IPv4Address.of("10.0.0.2"))
			.setRouterIP(IPv4Address.of("10.0.0.3"))
			.setServerID(IPv4Address.of("10.0.0.1"))
			.setServerMac(MacAddress.of("00:11:22:33:44:55"))
			.setDomainName("vlan0")
			.setSubnetMask(IPv4Address.of("10.0.0.0/24"))
			.setBroadcastIP(IPv4Address.of("10.0.0.255"))
			.setVlanMembers(set);
		dList = builder.build();
	}
}
