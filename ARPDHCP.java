package net.floodlightcontroller.sdn_arp_spoof_detection;

import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.dhcpserver.DHCPInstance;
import net.floodlightcontroller.dhcpserver.DHCPInstance.DHCPInstanceBuilder;
import net.floodlightcontroller.dhcpserver.IDHCPService;

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
		service.enableDHCP();
	}
	private void buildDHCP(){
		HashSet<VlanVid> set = new HashSet<VlanVid>();
		set.add(VlanVid.ofVlan(0));
		set.add(VlanVid.ofVlan(1));
		DHCPInstanceBuilder builder = new DHCPInstanceBuilder("vlan0").setEndIP(IPv4Address.of("192.168.1.254"))
			.setLeaseTimeSec(3600)
			.setIPforwarding(false)
			.setStartIP(IPv4Address.of("192.168.1.3"))
			.setRouterIP(IPv4Address.of("192.168.1.1"))
			.setServerID(IPv4Address.of("191.168.1.2"))
			.setServerMac(MacAddress.of("00:00:00:00:00:0a"))
			.setDomainName("local-domain")
			.setSubnetMask(IPv4Address.of("255.255.255.0"))
			.setBroadcastIP(IPv4Address.of("192.168.1.255"))
			.setVlanMembers(set);
		dList = builder.build();
	}
}
