package com.yourorg.netanalysis.model;
 
import java.time.Instant;
 
public class PacketRecord {
    public Instant timestamp;
    public String srcMac;
    public String dstMac;
    public String srcip;
    public String dstIp;
    public Integer srcPort;
    public Integer dstPort;
    public String protocol;
    public Integer iplen;
    public Integer payloadLen;
    public Integer tcpFlags;
 
    public PacketRecord() {
        this.timestamp = Instant.now();
    }
}
