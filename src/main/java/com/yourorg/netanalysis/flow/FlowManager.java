package com.yourorg.netanalysis.flow;

import com.yourorg.netanalysis.parser.PacketRecord;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class FlowManager {
    private final Map<String, Flow> flows = new ConcurrentHashMap<>();

    public String flowKey(PacketRecord pr) {
        return String.format("%s-%s-%s-%s-%s",
                pr.srcIp, pr.dstIp,
                pr.srcPort == null ? "0" : pr.srcPort,
                pr.dstPort == null ? "0" : pr.dstPort,
                pr.protocol == null ? "UNK" : pr.protocol);
    }

    public void addPacket(PacketRecord pr) {
        String k = flowKey(pr);
        flows.compute(k, (key, f) -> {
            if (f == null) f = new Flow(key, pr.timestamp);
            f.addPacket(pr.ipLen != null ? pr.ipLen : 0);
            return f;
        });
    }

    public Map<String, Flow> getFlows() { return flows; }
}
