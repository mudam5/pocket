package com.yourorg.netanalysis.parser;

public class PacketRecord {
    public String srcIp;
    public String dstIp;
    public Integer srcPort;
    public Integer dstPort;
    public int payloadLen;

    public boolean synFlag;
    public boolean ackFlag;
    public boolean finFlag;
    public boolean rstFlag;
}
