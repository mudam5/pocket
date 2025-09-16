package com.yourorg.netanalysis.parser;

import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.IpNumber;

public class PacketParser {

    public static PacketRecord parse(Packet p) {
        PacketRecord r = new PacketRecord();

        if (p.contains(EthernetPacket.class)) {
            EthernetPacket eth = p.get(EthernetPacket.class);
            r.srcMac = eth.getHeader().getSrcAddr().toString();
            r.dstMac = eth.getHeader().getDstAddr().toString();
        }

        if (p.contains(IpV4Packet.class)) {
            IpV4Packet ip = p.get(IpV4Packet.class);
            r.srcIp = ip.getHeader().getSrcAddr().getHostAddress();
            r.dstIp = ip.getHeader().getDstAddr().getHostAddress();
            r.ipLen = ip.getHeader().getTotalLengthAsInt();
            IpNumber proto = ip.getHeader().getProtocol();
            r.protocol = proto.name();

            if (proto.equals(IpNumber.TCP) && p.contains(TcpPacket.class)) {
                TcpPacket tcp = p.get(TcpPacket.class);
                r.srcPort = tcp.getHeader().getSrcPort().valueAsInt();
                r.dstPort = tcp.getHeader().getDstPort().valueAsInt();

                // Use built-in method for TCP flags
                r.tcpFlags = tcp.getHeader().getRawFlags();

                r.payloadLen = tcp.getPayload() != null ? tcp.getPayload().length() : 0;

            } else if (proto.equals(IpNumber.UDP) && p.contains(UdpPacket.class)) {
                UdpPacket udp = p.get(UdpPacket.class);
                r.srcPort = udp.getHeader().getSrcPort().valueAsInt();
                r.dstPort = udp.getHeader().getDstPort().valueAsInt();
                r.payloadLen = udp.getPayload() != null ? udp.getPayload().length() : 0;
            }
        }

        return r;
    }
}
