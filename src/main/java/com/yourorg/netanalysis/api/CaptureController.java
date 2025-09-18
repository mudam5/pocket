package com.yourorg.netanalysis.api;

import com.yourorg.netanalysis.capture.PcapCaptureService;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/capture")
public class CaptureController {

    private final PcapCaptureService captureService;

    public CaptureController(PcapCaptureService captureService) {
        this.captureService = captureService;
    }

    @PostMapping("/start/all")
    public String startAll(@RequestParam(required = false) String filter) {
        captureService.startCaptureOnAllInterfaces(filter, this::handlePacket, null);
        return "✅ Started capturing on ALL interfaces.";
    }

    @PostMapping("/start/{nifName}")
    public String startOne(@PathVariable String nifName,
                           @RequestParam(required = false) String filter) {
        try {
            PcapNetworkInterface nif = Pcaps.getDevByName(nifName);
            if (nif == null) {
                return "❌ No such interface: " + nifName;
            }
            captureService.startCaptureOnInterface(nif, filter, this::handlePacket, null);
            return "✅ Started capturing on interface: " + nifName;
        } catch (Exception e) {
            return "❌ Error: " + e.getMessage();
        }
    }

    @PostMapping("/stop/{nifName}")
    public String stopOne(@PathVariable String nifName) {
        captureService.stopCaptureOnInterface(nifName);
        return "🛑 Stopped capture on interface: " + nifName;
    }

    @PostMapping("/stop/all")
    public String stopAll() {
        captureService.stopAllCaptures();
        return "🛑 Stopped capture on ALL interfaces.";
    }

    @PostMapping("/read")
    public String readFile(@RequestParam String filePath) {
        try {
            captureService.readPcapFile(filePath, this::handlePacket);
            return "📂 Finished reading packets from file: " + filePath;
        } catch (Exception e) {
            return "❌ Error reading file: " + e.getMessage();
        }
    }

    @GetMapping("/interfaces")
    public List<PcapNetworkInterface> listInterfaces() throws Exception {
        return Pcaps.findAllDevs();
    }

    private void handlePacket(Packet packet) {
        System.out.println("📦 Captured packet: " + packet);
        // 👉 TODO: Parse and push structured data (src/dst IP, ports, protocol) to DB/Kafka
    }
}
