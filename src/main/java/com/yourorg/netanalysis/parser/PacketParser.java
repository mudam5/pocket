package com.yourorg.netanalysis.parser;
 
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.IpNumber;
 
import com.yourorg.netanalysis.parser.PacketRecord;
 
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
 
            if (proto.equals(IpNumber.TCP) && p.contains(TcpPacket.class)) {
                TcpPacket tcp = p.get(TcpPacket.class);
                TcpPacket.TcpHeader tcpHeader = tcp.getHeader();
 
                r.srcPort = tcpHeader.getSrcPort().valueAsInt();
                r.dstPort = tcpHeader.getDstPort().valueAsInt();
 
                int flags = 0;
                if (tcpHeader.getUrg()) flags |= 0x20;
                if (tcpHeader.getAck()) flags |= 0x10;
                if (tcpHeader.getPsh()) flags |= 0x08;
                if (tcpHeader.getRst()) flags |= 0x04;
                if (tcpHeader.getSyn()) flags |= 0x02;
                if (tcpHeader.getFin()) flags |= 0x01;
                r.tcpFlags = flags;
 
                r.payloadLen = (tcp.getPayload() != null) ? tcp.getPayload().length() : 0;
            }
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
 
