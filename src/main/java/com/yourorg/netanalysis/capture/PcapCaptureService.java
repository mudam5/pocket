package com.yourorg.netanalysis.capture;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

import java.io.IOException;
import java.sql.Timestamp;
import java.util.Map;
import java.util.concurrent.*;
import java.util.function.Consumer;

public class PcapCaptureService {

    private final Map<String, ExecutorService> activeCaptures = new ConcurrentHashMap<>();
    private final Map<String, PcapHandle> handleMap = new ConcurrentHashMap<>();
    private final Map<String, PcapDumper> dumperMap = new ConcurrentHashMap<>();

    /**
     * Start capture on all interfaces
     */
    public void startCaptureOnAllInterfaces(String filter,
                                            Consumer<Packet> packetConsumer,
                                            String dumpFilePath) {
        try {
            for (PcapNetworkInterface nif : Pcaps.findAllDevs()) {
                startCaptureOnInterface(nif, filter, packetConsumer, dumpFilePath);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to start capture on all interfaces", e);
        }
    }

    /**
     * Start capture on a single interface
     */
    public void startCaptureOnInterface(PcapNetworkInterface nif,
                                        String filter,
                                        Consumer<Packet> packetConsumer,
                                        String dumpFilePath) {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        activeCaptures.put(nif.getName(), executor);

        executor.submit(() -> {
            try {
                PcapHandle.Builder builder = new PcapHandle.Builder(nif.getName())
                        .snaplen(65536)
                        .promiscuousMode(PcapNetworkInterface.PromiscuousMode.PROMISCUOUS)
                        .timeoutMillis(10);

                if (filter != null && !filter.isEmpty()) {
                    builder.filter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
                }

                PcapHandle handle = builder.build();
                handleMap.put(nif.getName(), handle);

                PcapDumper dumper = null;
                if (dumpFilePath != null) {
                    dumper = handle.dumpOpen(dumpFilePath);
                    dumperMap.put(nif.getName(), dumper);
                }

                handle.loop(-1, (Packet packet) -> {
                    packetConsumer.accept(packet);
                    if (dumper != null) {
                        try {
                            dumper.dump(packet, new Timestamp(System.currentTimeMillis()));
                        } catch (IOException e) {
                            System.err.println("Failed to dump packet: " + e.getMessage());
                        }
                    }
                });

            } catch (Exception e) {
                System.err.println("Error capturing on interface " + nif.getName() + ": " + e.getMessage());
            }
        });
    }

    /**
     * Stop capture on one interface
     */
    public void stopCaptureOnInterface(String nifName) {
        try {
            PcapHandle handle = handleMap.remove(nifName);
            if (handle != null && handle.isOpen()) {
                handle.breakLoop();
                handle.close();
            }

            PcapDumper dumper = dumperMap.remove(nifName);
            if (dumper != null) {
                dumper.close();
            }

            ExecutorService executor = activeCaptures.remove(nifName);
            if (executor != null) {
                executor.shutdownNow();
            }

        } catch (Exception e) {
            throw new RuntimeException("Failed to stop capture on " + nifName, e);
        }
    }

    /**
     * Stop capture on all interfaces
     */
    public void stopAllCaptures() {
        for (String nifName : handleMap.keySet()) {
            stopCaptureOnInterface(nifName);
        }
    }

    /**
     * Read a pcap file and process packets
     */
    public void readPcapFile(String filePath, Consumer<Packet> packetConsumer) {
        try (PcapHandle handle = Pcaps.openOffline(filePath)) {
            Packet packet;
            while ((packet = handle.getNextPacket()) != null) {
                packetConsumer.accept(packet);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to read pcap file: " + filePath, e);
        }
    }
}
