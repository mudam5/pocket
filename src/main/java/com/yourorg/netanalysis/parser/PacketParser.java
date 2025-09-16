package com.yourorg.netanalysis.parser;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.IpV4Packet;

import java.util.ArrayList;
import java.util.List;

public class PacketParser {

    public static class PacketRecord {
        public String srcIp;
        public String dstIp;
        public Integer srcPort;
        public Integer dstPort;
        public Integer payloadLen;

        @Override
        public String toString() {
            return "PacketRecord{" +
                    "srcIp='" + srcIp + '\'' +
                    ", dstIp='" + dstIp + '\'' +
                    ", srcPort=" + srcPort +
                    ", dstPort=" + dstPort +
                    ", payloadLen=" + payloadLen +
                    '}';
        }
    }

    // Parse a single packet
    public PacketRecord parse(Packet packet) {
        PacketRecord r = new PacketRecord();

        // IPv4 layer
        IpV4Packet ipV4 = packet.get(IpV4Packet.class);
        if (ipV4 != null) {
            r.srcIp = ipV4.getHeader().getSrcAddr().getHostAddress();
            r.dstIp = ipV4.getHeader().getDstAddr().getHostAddress();
        }

        // TCP layer
        TcpPacket tcp = packet.get(TcpPacket.class);
        if (tcp != null) {
            r.srcPort = tcp.getHeader().getSrcPort().valueAsInt();
            r.dstPort = tcp.getHeader().getDstPort().valueAsInt();
            r.payloadLen = tcp.getPayload() != null ? tcp.getPayload().length() : 0;
        }

        // UDP layer
        UdpPacket udp = packet.get(UdpPacket.class);
        if (udp != null) {
            r.srcPort = udp.getHeader().getSrcPort().valueAsInt();
            r.dstPort = udp.getHeader().getDstPort().valueAsInt();
            r.payloadLen = udp.getPayload() != null ? udp.getPayload().length() : 0;
        }

        return r;
    }

    // Parse a PCAP file
    public List<PacketRecord> parsePcap(String pcapFile) throws Exception {
        List<PacketRecord> records = new ArrayList<>();

        // Import these in CaptureController if needed
        org.pcap4j.core.PcapHandle handle = org.pcap4j.core.Pcaps.openOffline(pcapFile);
        Packet packet;

        while ((packet = handle.getNextPacket()) != null) {
            try {
                PacketRecord record = parse(packet);
                records.add(record);
            } catch (Exception e) {
                System.err.println("Failed to parse packet: " + e.getMessage());
            }
        }

        handle.close();
        return records;
    }
}
