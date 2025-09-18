package com.yourorg.netanalysis.capture;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

import java.io.EOFException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

public class PcapCaptureService {

    private final Map<String, PcapHandle> activeCaptures = new ConcurrentHashMap<>();

    /**
     * Start capture on ALL interfaces
     */
    public void startCaptureOnAllInterfaces(String filter,
                                            Consumer<Packet> packetHandler,
                                            String filePrefix) throws Exception {
        for (PcapNetworkInterface nif : Pcaps.findAllDevs()) {
            startCaptureOnInterface(nif, filter, packetHandler, filePrefix);
        }
    }

    /**
     * Start capture on ONE interface
     */
    public void startCaptureOnInterface(PcapNetworkInterface nif,
                                        String filter,
                                        Consumer<Packet> packetHandler,
                                        String filePrefix) throws Exception {
        String nifName = nif.getName();
        if (activeCaptures.containsKey(nifName)) {
            throw new IllegalStateException("Already capturing on " + nifName);
        }

        PcapHandle.Builder builder = new PcapHandle.Builder(nifName)
                .snaplen(65536)
                .promiscuousMode(PcapNetworkInterface.PromiscuousMode.PROMISCUOUS)
                .timeoutMillis(10);

        PcapHandle handle = builder.build();

        if (filter != null && !filter.isEmpty()) {
            handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
        }

        activeCaptures.put(nifName, handle);

        Thread captureThread = new Thread(() -> {
            try {
                handle.loop(-1, packet -> {
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
                activeCaptures.remove(nifName);
            }
        });

        captureThread.setDaemon(true);
        captureThread.start();
    }

    /**
     * Stop capture on ONE interface
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
     * Read packets from a .pcap file
     */
    public void readPcapFile(String filePath, Consumer<Packet> packetHandler) throws Exception {
        try (PcapHandle handle = Pcaps.openOffline(filePath)) {
            while (true) {
                try {
                    Packet packet = handle.getNextPacketEx();
                    packetHandler.accept(packet);
                } catch (EOFException e) {
                    break;
                }
            }
        }
    }
}
