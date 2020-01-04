package net.floodlightcontroller.sdn_arp_spoof_detection.web;

import java.io.IOException;
import java.util.HashMap;

import org.projectfloodlight.openflow.types.OFPort;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonGenerator.Feature;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.sdn_arp_spoof_detection.*;

public class ArpJsonSerializer extends JsonSerializer<ArpJsonMap> {

	@Override
	public void serialize(ArpJsonMap jmap, JsonGenerator gen, SerializerProvider serial)			throws IOException, JsonProcessingException {
		// TODO Auto-generated method stub
		gen.configure(Feature.WRITE_NUMBERS_AS_STRINGS,true);
		if(jmap == null){
			gen.writeStartObject();
			gen.writeString("no entry present till now");
			gen.writeEndObject();
		}
		HashMap<IOFSwitch,HashMap<OFPort,IPMacPair>> map = jmap.getMap();
		if(map.keySet()!=null){
			for(IOFSwitch sw : map.keySet()){
				gen.writeArrayFieldStart(String.valueOf(sw.getId().getLong()));
				HashMap<OFPort,IPMacPair> inMap = map.get(sw);
				if(inMap.keySet() != null){
					for(OFPort port : inMap.keySet()){
						gen.writeStartObject();
						gen.writeStringField(port.toString(),inMap.get(port).getIp().toString());
						gen.writeEndObject();
					}
				}
				gen.writeEndArray();
			}
		}
	}
}
