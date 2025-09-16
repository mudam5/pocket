package com.yourorg.netanalysis.parser;
 
import org.pcap4j.*;
 
public class PacketParser {
 
    public static PacketRecord parse(Packet p) {
        PacketRecord r = new PacketRecord();
 
        if (p.contains(IpV4Packet.class)) {
            IpV4Packet ip = p.get(IpV4Packet.class);
 
            r.srcIp = ip.getHeader().getSrcAddr().getHostAddress();
            r.dstIp = ip.getHeader().getDstAddr().getHostAddress();
            r.ipLen = ip.getHeader().getTotalLengthAsInt();
 
            IpNumber proto = ip.getHeader().getProtocol();
            r.protocol = proto.name();
 
            // Handle TCP packets
            if (proto.equals(IpNumber.TCP) && p.contains(TcpPacket.class)) {
                TcpPacket tcp = p.get(TcpPacket.class);
 
                r.srcPort = tcp.getHeader().getSrcPort().valueAsInt();
                r.dstPort = tcp.getHeader().getDstPort().valueAsInt();
 
                // Check individual TCP flags
                StringBuilder flags = new StringBuilder();
                if (tcp.getHeader().getFin()) flags.append("FIN ");
                if (tcp.getHeader().getSyn()) flags.append("SYN ");
                if (tcp.getHeader().getRst()) flags.append("RST ");
                if (tcp.getHeader().getPsh()) flags.append("PSH ");
                if (tcp.getHeader().getAck()) flags.append("ACK ");
                if (tcp.getHeader().getUrg()) flags.append("URG ");
                if (tcp.getHeader().getEce()) flags.append("ECE ");
                if (tcp.getHeader().getCwr()) flags.append("CWR ");
                r.tcpFlags = flags.toString().trim();
 
                r.payloadLen = (tcp.getPayload() != null) ? tcp.getPayload().length() : 0;
            }
 
            // Handle UDP packets
            else if (proto.equals(IpNumber.UDP) && p.contains(UdpPacket.class)) {
                UdpPacket udp = p.get(UdpPacket.class);
 
                r.srcPort = udp.getHeader().getSrcPort().valueAsInt();
                r.dstPort = udp.getHeader().getDstPort().valueAsInt();
                r.payloadLen = (udp.getPayload() != null) ? udp.getPayload().length() : 0;
            }
        }
 
        return r;
    }
}
