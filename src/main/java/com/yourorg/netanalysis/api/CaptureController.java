package com.yourorg.netanalysis.api;

import com.yourorg.netanalysis.capture.PcapCaptureService;
import com.yourorg.netanalysis.flow.FlowManager;
import com.yourorg.netanalysis.parser.PacketParser;
import com.yourorg.netanalysis.parser.PacketRecord;
import com.yourorg.netanalysis.store.entities.PacketEntity;
import com.yourorg.netanalysis.store.repository.PacketRepository;
import org.pcap4j.packet.Packet;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v1/capture")
public class CaptureController {

    private final PcapCaptureService captureService;
    private final FlowManager flowManager = new FlowManager();
    private final PacketRepository packetRepository;

    public CaptureController(PcapCaptureService captureService, PacketRepository packetRepository) {
        this.captureService = captureService;
        this.packetRepository = packetRepository;
    }

    @PostMapping("/start")
    public String start(@RequestParam String iface) throws Exception {
        // live capture with packet consumer
        captureService.startLiveCapture(iface, null, this::handlePacket);
        return "started";
    }

    @PostMapping("/stop")
    public String stop() {
        captureService.stopCapture();
        return "stopped";
    }

    @PostMapping("/read-pcap")
    public String readPcap(@RequestParam String path) throws Exception {
        // offline pcap reader with packet consumer
        captureService.readPcapFile(path, this::handlePacket);
        return "processed";
    }

    @GetMapping("/flows")
    public List<String> flows() {
        return flowManager.getFlows().keySet().stream().collect(Collectors.toList());
    }

    /**
     * Handle each captured or read packet.
     */
    private void handlePacket(Packet p) {
        if (p == null) {
            return;
        }

        PacketRecord pr = PacketParser.parse(p);
        flowManager.addPacket(pr);

        PacketEntity e = new PacketEntity();
        e.timestamp = pr.timestamp;
        e.srcIp = pr.srcIp;
        e.dstIp = pr.dstIp;
        e.srcPort = pr.srcPort;
        e.dstPort = pr.dstPort;
        e.protocol = pr.protocol;
        e.ipLen = pr.ipLen;

        try {
            packetRepository.save(e);
        } catch (Exception ex) {
            // swallow DB errors to not break capture loop
            ex.printStackTrace();
        }
    }
}
