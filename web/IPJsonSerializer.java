package net.floodlightcontroller.sdn_arp_spoof_detection.web;

import java.io.IOException;
import java.util.HashMap;

import org.projectfloodlight.openflow.types.IPv4Address;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonGenerator.Feature;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

import net.floodlightcontroller.core.IOFSwitch;

public class IPJsonSerializer extends JsonSerializer<IPJsonMap> {

	@Override
	public void serialize(IPJsonMap jmap, JsonGenerator gen, SerializerProvider serial)			throws IOException, JsonProcessingException {
		// TODO Auto-generated method stub
		gen.configure(Feature.WRITE_NUMBERS_AS_STRINGS,true);
		if(jmap == null){
			gen.writeStartObject();
			gen.writeString("no entry present till now");
			gen.writeEndObject();
		}
		HashMap<IPv4Address,IOFSwitch> map = jmap.getMap();
		if(map.keySet()!=null){
			gen.writeStartArray();
			for(IPv4Address ip : map.keySet()){
				gen.writeStartObject();
				gen.writeStringField(ip.toString(),map.get(ip).getId().toString());
				gen.writeEndObject();
			}
			gen.writeEndArray();
		}
	}
}
