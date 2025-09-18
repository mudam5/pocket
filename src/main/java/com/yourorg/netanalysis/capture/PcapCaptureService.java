package com.yourorg.netanalysis.capture;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

@Service
public class PcapCaptureService {

    // Track active captures: interface name -> PcapHandle
    private final Map<String, PcapHandle> activeCaptures = new ConcurrentHashMap<>();
    private final ExecutorService executor = Executors.newCachedThreadPool();

    /**
     * Start capture on ALL interfaces
     */
    public void startCaptureOnAllInterfaces(String filter, Consumer<Packet> packetHandler, String outputFile) {
        try {
            for (PcapNetworkInterface nif : Pcaps.findAllDevs()) {
                startCaptureOnInterface(nif, filter, packetHandler, outputFile);
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
                                        Consumer<Packet> packetHandler,
                                        String outputFile) {
        if (activeCaptures.containsKey(nif.getName())) {
            throw new IllegalStateException("Capture already running on interface: " + nif.getName());
        }

        try {
            int snapLen = 65536;
            PcapHandle handle = new PcapHandle.Builder(nif.getName())
                    .snaplen(snapLen)
                    .promiscuousMode(PromiscuousMode.PROMISCUOUS)
                    .timeoutMillis(10)
                    .build();

            if (filter != null && !filter.isBlank()) {
                handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
            }

            activeCaptures.put(nif.getName(), handle);

            // Run capture in background thread
            executor.submit(() -> {
                try {
                    handle.loop(-1, (PacketListener) packet -> {
                        try {
                            packetHandler.accept(packet);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    });
                } catch (InterruptedException ignored) {
                } catch (PcapNativeException | NotOpenException e) {
                    e.printStackTrace();
                } finally {
                    handle.close();
                    activeCaptures.remove(nif.getName());
                }
            });

        } catch (Exception e) {
            throw new RuntimeException("Failed to start capture on interface: " + nif.getName(), e);
        }
    }

    /**
     * Stop capture on a single interface
     */
    public void stopCaptureOnInterface(String nifName) {
        PcapHandle handle = activeCaptures.get(nifName);
        if (handle != null && handle.isOpen()) {
            try {
                handle.breakLoop();
            } catch (NotOpenException ignored) {
            } finally {
                handle.close();
                activeCaptures.remove(nifName);
            }
        }
    }

    /**
     * Stop ALL captures
     */
    public void stopAllCaptures() {
        for (String nifName : activeCaptures.keySet()) {
            stopCaptureOnInterface(nifName);
        }
    }

    /**
     * Read packets from an offline pcap file
     */
    public void readPcapFile(String filePath, Consumer<Packet> packetHandler) throws PcapNativeException {
        try (PcapHandle reader = Pcaps.openOffline(filePath)) {
            Packet packet;
            while ((packet = reader.getNextPacket()) != null) {
                packetHandler.accept(packet);
            }
        } catch (Exception e) {
            throw new RuntimeException("Error reading pcap file: " + filePath, e);
        }
    }
}
