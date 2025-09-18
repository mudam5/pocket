package com.yourorg.netanalysis.capture;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.EOFException;
import java.sql.Timestamp;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

@Service
public class PcapCaptureService {
    private static final Logger logger = LoggerFactory.getLogger(PcapCaptureService.class);

    private final ExecutorService exec = Executors.newCachedThreadPool();
    private final Map<String, PcapHandle> handleMap = new ConcurrentHashMap<>();
    private final Map<String, PcapDumper> dumperMap = new ConcurrentHashMap<>();
    private final AtomicBoolean capturing = new AtomicBoolean(false);

    /**
     * Start capturing packets on all available interfaces
     */
    public void startCaptureOnAllInterfaces(String bpf, Consumer<Packet> packetConsumer, String dumpFilePath) throws PcapNativeException {
        if (capturing.get()) {
            logger.warn("Capture already running");
            return;
        }
        capturing.set(true);

        List<PcapNetworkInterface> nifs = Pcaps.findAllDevs();
        if (nifs == null || nifs.isEmpty()) {
            throw new IllegalStateException("No network interfaces found");
        }

        for (PcapNetworkInterface nif : nifs) {
            exec.submit(() -> startCaptureOnInterface(nif, bpf, packetConsumer, dumpFilePath));
        }
    }

    /**
     * Start capture on a specific interface
     */
    private void startCaptureOnInterface(PcapNetworkInterface nif, String bpf, Consumer<Packet> packetConsumer, String dumpFilePath) {
        int snapLen = 65536;
        try {
            PcapHandle handle = new PcapHandle.Builder(nif.getName())
                    .snaplen(snapLen)
                    .promiscuousMode(PromiscuousMode.PROMISCUOUS)
                    .timeoutMillis(10)
                    .build();

            if (bpf != null && !bpf.isBlank()) {
                try {
                    handle.setFilter(bpf, BpfProgram.BpfCompileMode.OPTIMIZE);
                } catch (NotOpenException e) {
                    logger.error("Failed to set filter on {}", nif.getName(), e);
                }
            }

            handleMap.put(nif.getName(), handle);

            PcapDumper dumper = null;
            if (dumpFilePath != null) {
                try {
                    dumper = handle.dumpOpen(dumpFilePath + "_" + nif.getName() + ".pcap");
                    dumperMap.put(nif.getName(), dumper);
                } catch (NotOpenException e) {
                    logger.error("Failed to open dumper for {}", nif.getName(), e);
                }
            }

            final PcapDumper finalDumper = dumper;

            logger.info("Starting capture on interface {}", nif.getName());

            handle.loop(-1, (Packet packet) -> {
                try {
                    packetConsumer.accept(packet);
                    if (finalDumper != null) {
                        try {
                            finalDumper.dump(packet, new Timestamp(System.currentTimeMillis()));
                        } catch (NotOpenException e) {
                            logger.error("Failed to dump packet on {}", nif.getName(), e);
                        }
                    }
                } catch (Exception ex) {
                    logger.error("Error processing packet on {}", nif.getName(), ex);
                }
            });

        } catch (Exception e) {
            logger.error("Error starting capture on {}", nif.getName(), e);
        }
    }

    /**
     * Stop all captures
     */
    public void stopCapture() {
        capturing.set(false);

        for (Map.Entry<String, PcapHandle> entry : handleMap.entrySet()) {
            PcapHandle handle = entry.getValue();
            if (handle != null && handle.isOpen()) {
                try {
                    handle.breakLoop();
                    handle.close();
                } catch (NotOpenException e) {
                    logger.warn("Handle already closed for {}", entry.getKey());
                }
            }
        }
        handleMap.clear();

        for (Map.Entry<String, PcapDumper> entry : dumperMap.entrySet()) {
            PcapDumper dumper = entry.getValue();
            if (dumper != null) {
                try {
                    dumper.close();
                } catch (NotOpenException e) {
                    logger.warn("Dumper already closed for {}", entry.getKey());
                }
            }
        }
        dumperMap.clear();

        exec.shutdownNow();
        logger.info("Stopped all captures");
    }

    /**
     * Read packets from a PCAP file
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
                    break; // end of file
                } catch (TimeoutException ignored) {
                    // skip timeouts
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
