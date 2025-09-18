package com.yourorg.netanalysis.capture;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.EOFException;
import java.util.concurrent.*;
import java.util.function.Consumer;
import java.util.concurrent.TimeoutException;

@Service
public class PcapCaptureService {
    private static final Logger logger = LoggerFactory.getLogger(PcapCaptureService.class);
    private final ExecutorService exec = Executors.newSingleThreadExecutor();
    private PcapHandle handle;

    /**
     * Start live capture on a given network interface.
     */
    public void startLiveCapture(String nifName, String bpf, Consumer<Packet> packetConsumer) throws PcapNativeException {
        PcapNetworkInterface nif = Pcaps.getDevByName(nifName);
        if (nif == null) {
            throw new IllegalArgumentException("No such interface: " + nifName);
        }

        int snapLen = 65536;
        PcapHandle.Builder phb = new PcapHandle.Builder(nif.getName())
                .snaplen(snapLen)
                .promiscuousMode(PromiscuousMode.PROMISCUOUS)
                .timeoutMillis(10);

        try {
            handle = phb.build();
            if (bpf != null && !bpf.isBlank()) {
                handle.setFilter(bpf, BpfProgram.BpfCompileMode.OPTIMIZE);
            }
        } catch (PcapNativeException e) {
            logger.error("Failed to build pcap handle", e);
            throw e;
        } catch (NotOpenException e) {
            logger.error("Failed to set filter on handle", e);
        }

        PacketListener listener = packet -> {
            try {
                // Log each captured packet for debugging
                logger.info("Captured packet: {}", packet);
                packetConsumer.accept(packet);
            } catch (Exception ex) {
                logger.error("Error processing packet", ex);
            }
        };

        exec.submit(() -> {
            try {
                logger.info("Starting packet capture on interface: {}", nifName);
                handle.loop(-1, listener);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (PcapNativeException | NotOpenException e) {
                logger.error("pcap loop error", e);
            }
        });
    }

    /**
     * Stop live capture.
     */
    public void stopCapture() {
        if (handle != null && handle.isOpen()) {
            try {
                handle.breakLoop();
            } catch (NotOpenException e) {
                logger.warn("Handle already closed", e);
            } finally {
                handle.close();
            }
        }
        exec.shutdownNow();
    }

    /**
     * Read packets from an offline pcap file.
     */
    public void readPcapFile(String filePath, Consumer<Packet> packetConsumer) throws PcapNativeException {
        try (PcapHandle reader = Pcaps.openOffline(filePath)) {
            Packet packet;
            while (true) {
                try {
                    packet = reader.getNextPacketEx();
                    logger.info("Read packet from file: {}", packet);
                    packetConsumer.accept(packet);
                } catch (EOFException eof) {
                    break; // finished reading file
                } catch (TimeoutException ignored) {
                    // skip timeouts in offline mode
                } catch (NotOpenException e) {
                    logger.error("Reader unexpectedly closed", e);
                    break;
                }
            }
        } catch (PcapNativeException e) {
            logger.error("Failed to open pcap file: {}", filePath, e);
            throw e;
        }
    }
}
