package com.yourorg.netanalysis.parser;
 
import java.time.Instant;
 
public class PacketRecord {
    public Instant timestamp;
    public String srcMac;
    public String dstMac;
    public String srcIp;
    public String dstIp;
    public Integer srcPort;
    public Integer dstPort;
    public String protocol;
    public Integer ipLen;
    public Integer payloadLen;
    public Integer tcpFlags;
 
    public PacketRecord() {
        this.timestamp = Instant.now();
    }
}
