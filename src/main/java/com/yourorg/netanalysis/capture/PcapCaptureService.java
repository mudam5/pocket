package com.yourorg.netanalysis.capture;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;

@Service
public class PcapCaptureService {

    private static final Logger logger = LoggerFactory.getLogger(PcapCaptureService.class);

    // One thread pool to manage per-interface capture tasks
    private final ExecutorService captureExecutor = Executors.newCachedThreadPool();

    // Track running handles and futures keyed by interface name
    private final Map<String, PcapHandle> handles = new ConcurrentHashMap<>();
    private final Map<String, Future<?>> captureFutures = new ConcurrentHashMap<>();
    private final Map<String, PcapDumper> dumpers = new ConcurrentHashMap<>();

    /**
     * Start captures on all available interfaces.
     *
     * @param bpfFilter       BPF filter string or null/blank for no filter (captures everything)
     * @param perPacketAction consumer that receives PacketInfo for each captured packet
     * @param dumpDir         directory to write per-interface .pcap files; if null -> no dump
     * @throws PcapNativeException when pcap fails to access devices
     */
    public void startCaptureOnAllInterfaces(String bpfFilter,
                                            Consumer<PacketInfo> perPacketAction,
                                            Path dumpDir) throws PcapNativeException {

        List<PcapNetworkInterface> nifs = Pcaps.findAllDevs();
        if (nifs == null || nifs.isEmpty()) {
            throw new IllegalStateException("No network interfaces found for packet capture");
        }

        // Create dump directory if requested
        if (dumpDir != null) {
            try {
                Files.createDirectories(dumpDir);
            } catch (IOException e) {
                logger.warn("Could not create dump directory {}: {}", dumpDir, e.getMessage());
            }
        }

        for (PcapNetworkInterface nif : nifs) {
            String name = nif.getName();
            // Skip loopback interfaces unless you explicitly want them
            // To include loopback, remove this check.
            if (nif.isLoopBack()) {
                logger.info("Skipping loopback interface: {}", name);
                continue;
            }

            // Start per-interface capture
            startCaptureOnInterface(nif, bpfFilter, perPacketAction, dumpDir);
        }
    }

    /**
     * Start capture on a single interface.
     */
    public void startCaptureOnInterface(PcapNetworkInterface nif,
                                        String bpfFilter,
                                        Consumer<PacketInfo> perPacketAction,
                                        Path dumpDir) {
        final String ifName = nif.getName();
        if (handles.containsKey(ifName)) {
            logger.warn("Capture already running on interface {}", ifName);
            return;
        }

        final int snapLen = 65536; // capture full packets
        final int timeoutMillis = 10;
        final PromiscuousMode mode = PromiscuousMode.PROMISCUOUS;

        PcapHandle handle;
        try {
            handle = new PcapHandle.Builder(ifName)
                    .snaplen(snapLen)
                    .promiscuousMode(mode)
                    .timeoutMillis(timeoutMillis)
                    .build();

            if (bpfFilter != null && !bpfFilter.isBlank()) {
                handle.setFilter(bpfFilter, BpfProgram.BpfCompileMode.OPTIMIZE);
            }
        } catch (PcapNativeException | NotOpenException e) {
            logger.error("Failed to open handle for interface {}: {}", ifName, e.getMessage());
            return;
        }

        // Optionally create dumper
        PcapDumper dumper = null;
        if (dumpDir != null) {
            try {
                Path out = dumpDir.resolve(ifName + "-" + Instant.now().toEpochMilli() + ".pcap");
                dumper = handle.dumpOpen(out.toString());
                dumpers.put(ifName, dumper);
                logger.info("PCAP dumper opened for {} at {}", ifName, out);
            } catch (PcapNativeException e) {
                logger.warn("Failed to open dumper for interface {}: {}", ifName, e.getMessage());
            }
        }

        handles.put(ifName, handle);

        PacketListener listener = packet -> {
            // Dump raw packet if dumper exists
            try {
                if (dumper != null) {
                    dumper.dump(packet, handle.getTimestamp());
                }
            } catch (NotOpenException e) {
                logger.debug("Dumper not open for {}: {}", ifName, e.getMessage());
            }

            // Parse / classify packet and forward
            PacketInfo info = classifyPacket(packet, ifName, handle);
            try {
                perPacketAction.accept(info);
            } catch (Exception ex) {
                logger.error("Error in perPacketAction for {}: {}", ifName, ex.getMessage(), ex);
            }
        };

        // Submit capture loop
        Future<?> future = captureExecutor.submit(() -> {
            try {
                logger.info("Starting capture on interface {} (filter='{}')", ifName, bpfFilter);
                handle.loop(-1, listener); // -1 => infinite loop until breakLoop()
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                logger.info("Capture thread interrupted for {}", ifName);
            } catch (PcapNativeException | NotOpenException e) {
                logger.error("Capture failed on {}: {}", ifName, e.getMessage(), e);
            } finally {
                // cleanup if loop exits
                try {
                    if (dumper != null && !dumper.isClosed()) {
                        dumper.close();
                    }
                } catch (Exception ignore) {}
                try {
                    if (handle != null && handle.isOpen()) {
                        handle.close();
                    }
                } catch (Exception ignore) {}
                handles.remove(ifName);
                dumpers.remove(ifName);
                captureFutures.remove(ifName);
                logger.info("Capture loop finished for {}", ifName);
            }
        });

        captureFutures.put(ifName, future);
    }

    /**
     * Gracefully stop capture on a specific interface.
     */
    public void stopCaptureOnInterface(String ifName) {
        PcapHandle handle = handles.get(ifName);
        if (handle != null) {
            try {
                handle.breakLoop();
            } catch (NotOpenException e) {
                logger.warn("Handle not open while trying to break loop for {}: {}", ifName, e.getMessage());
            } finally {
                try { handle.close(); } catch (Exception ignore) {}
            }
        }

        Future<?> f = captureFutures.get(ifName);
        if (f != null) {
            f.cancel(true);
        }

        PcapDumper dumper = dumpers.get(ifName);
        if (dumper != null && !dumper.isClosed()) {
            try { dumper.close(); } catch (Exception ignore) {}
        }

        handles.remove(ifName);
        captureFutures.remove(ifName);
        dumpers.remove(ifName);

        logger.info("Stopped capture on interface {}", ifName);
    }

    /**
     * Stop ALL running captures.
     */
    public void stopAllCaptures() {
        // Copy keys to avoid concurrent modification
        List<String> ifNames = new ArrayList<>(handles.keySet());
        for (String ifName : ifNames) {
            stopCaptureOnInterface(ifName);
        }
        // shutdown executor if you want to completely stop service threads
        // captureExecutor.shutdownNow();
    }

    /**
     * Classify packet into a lightweight info structure.
     */
    private PacketInfo classifyPacket(Packet packet, String ifName, PcapHandle handle) {
        PacketInfo info = new PacketInfo();
        info.ifName = ifName;
        info.timestamp = handle != null ? handle.getTimestamp() : Instant.now();

        // Try Ethernet -> IPv4/IPv6 -> Transport
        EthernetPacket eth = packet.get(EthernetPacket.class);
        if (eth != null) {
            info.srcMac = eth.getHeader().getSrcAddr().toString();
            info.dstMac = eth.getHeader().getDstAddr().toString();
            Packet payload = eth.getPayload();
            IpV4Packet ipv4 = payload.get(IpV4Packet.class);
            IpV6Packet ipv6 = payload.get(IpV6Packet.class);
            if (ipv4 != null) {
                info.protocol = "IPv4";
                info.srcAddr = ipv4.getHeader().getSrcAddr().getHostAddress();
                info.dstAddr = ipv4.getHeader().getDstAddr().getHostAddress();
                Packet t = ipv4.getPayload();
                fillTransportInfo(t, info);
            } else if (ipv6 != null) {
                info.protocol = "IPv6";
                info.srcAddr = ipv6.getHeader().getSrcAddr().getHostAddress();
                info.dstAddr = ipv6.getHeader().getDstAddr().getHostAddress();
                Packet t = ipv6.getPayload();
                fillTransportInfo(t, info);
            } else {
                // Non-IP ethernet payload
                info.protocol = "ETHERNET";
            }
        } else {
            // Not ethernet (e.g., loopback); try IP directly
            IpV4Packet ipv4 = packet.get(IpV4Packet.class);
            IpV6Packet ipv6 = packet.get(IpV6Packet.class);
            if (ipv4 != null) {
                info.protocol = "IPv4";
                info.srcAddr = ipv4.getHeader().getSrcAddr().getHostAddress();
                info.dstAddr = ipv4.getHeader().getDstAddr().getHostAddress();
                fillTransportInfo(ipv4.getPayload(), info);
            } else if (ipv6 != null) {
                info.protocol = "IPv6";
                info.srcAddr = ipv6.getHeader().getSrcAddr().getHostAddress();
                info.dstAddr = ipv6.getHeader().getDstAddr().getHostAddress();
                fillTransportInfo(ipv6.getPayload(), info);
            } else {
                info.protocol = "UNKNOWN";
            }
        }

        return info;
    }

    private void fillTransportInfo(Packet transport, PacketInfo info) {
        if (transport == null) {
            return;
        }
        TcpPacket tcp = transport.get(TcpPacket.class);
        UdpPacket udp = transport.get(UdpPacket.class);
        IcmpV4CommonPacket icmp4 = transport.get(IcmpV4CommonPacket.class);
        IcmpV6CommonPacket icmp6 = transport.get(IcmpV6CommonPacket.class);

        if (tcp != null) {
            info.transport = "TCP";
            info.srcPort = tcp.getHeader().getSrcPort().valueAsInt();
            info.dstPort = tcp.getHeader().getDstPort().valueAsInt();
        } else if (udp != null) {
            info.transport = "UDP";
            info.srcPort = udp.getHeader().getSrcPort().valueAsInt();
            info.dstPort = udp.getHeader().getDstPort().valueAsInt();
        } else if (icmp4 != null || icmp6 != null) {
            info.transport = "ICMP";
        } else {
            info.transport = "OTHER";
        }
    }

    /**
     * Helper POJO carrying parsed packet details (lightweight).
     */
    public static class PacketInfo {
        public String ifName;
        public Instant timestamp;
        public String srcMac;
        public String dstMac;
        public String protocol;   // IPv4/IPv6/ETHERNET/UNKNOWN
        public String srcAddr;
        public String dstAddr;
        public String transport;  // TCP/UDP/ICMP/OTHER
        public Integer srcPort;
        public Integer dstPort;

        @Override
        public String toString() {
            return "PacketInfo{" +
                    "ifName='" + ifName + '\'' +
                    ", timestamp=" + timestamp +
                    ", srcMac='" + srcMac + '\'' +
                    ", dstMac='" + dstMac + '\'' +
                    ", protocol='" + protocol + '\'' +
                    ", srcAddr='" + srcAddr + '\'' +
                    ", dstAddr='" + dstAddr + '\'' +
                    ", transport='" + transport + '\'' +
                    ", srcPort=" + srcPort +
                    ", dstPort=" + dstPort +
                    '}';
        }
    }
}
