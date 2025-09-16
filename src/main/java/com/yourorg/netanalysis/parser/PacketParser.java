package com.yourorg.netanalysis.parser;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

// IMPORT PacketRecord
import com.yourorg.netanalysis.model.PacketRecord;

public class PacketParser {

    // Make parse() non-static
    public PacketRecord parse(Packet packet) throws PcapNativeException, NotOpenException {
        PacketRecord r = new PacketRecord();

        IpV4Packet ipV4 = packet.get(IpV4Packet.class);
        if (ipV4 != null) {
            r.srcIp = ipV4.getHeader().getSrcAddr().getHostAddress();
            r.dstIp = ipV4.getHeader().getDstAddr().getHostAddress();
        }

        TcpPacket tcp = packet.get(TcpPacket.class);
        if (tcp != null) {
            r.srcPort = tcp.getHeader().getSrcPort().valueAsInt();
            r.dstPort = tcp.getHeader().getDstPort().valueAsInt();
            r.payloadLen = tcp.getPayload() != null ? tcp.getPayload().length() : 0;

            r.synFlag = tcp.getHeader().getSyn();
            r.ackFlag = tcp.getHeader().getAck();
            r.finFlag = tcp.getHeader().getFin();
            r.rstFlag = tcp.getHeader().getRst();
        }

        UdpPacket udp = packet.get(UdpPacket.class);
        if (udp != null) {
            r.srcPort = udp.getHeader().getSrcPort().valueAsInt();
            r.dstPort = udp.getHeader().getDstPort().valueAsInt();
            r.payloadLen = udp.getPayload() != null ? udp.getPayload().length() : 0;
        }

        return r;
    }
}
