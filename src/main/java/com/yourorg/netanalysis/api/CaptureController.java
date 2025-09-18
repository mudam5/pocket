package com.yourorg.netanalysis.api;

import com.yourorg.netanalysis.capture.PcapCaptureService;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/capture")
public class CaptureController {

    private final PcapCaptureService captureService;

    public CaptureController(PcapCaptureService captureService) {
        this.captureService = captureService;
    }

    /**
     * Start capturing on ALL interfaces
     */
    @PostMapping("/start/all")
    public ResponseEntity<?> startAll(@RequestParam(required = false) String filter,
                                      @RequestParam(defaultValue = "capture") String filePrefix) {
        try {
            captureService.startCaptureOnAllInterfaces(filter, this::handlePacket, filePrefix);
            return ResponseEntity.ok(Map.of(
                    "status", "✅ started",
                    "interfaces", Pcaps.findAllDevs().stream()
                            .map(PcapNetworkInterface::getName)
                            .collect(Collectors.toList())
            ));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Start capturing on a single interface
     */
    @PostMapping("/start/{nifName}")
    public ResponseEntity<?> startOne(@PathVariable String nifName,
                                      @RequestParam(required = false) String filter,
                                      @RequestParam(defaultValue = "capture") String filePrefix) {
        try {
            PcapNetworkInterface nif = Pcaps.getDevByName(nifName);
            if (nif == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "No such interface: " + nifName));
            }
            captureService.startCaptureOnInterface(nif, filter, this::handlePacket, filePrefix);
            return ResponseEntity.ok(Map.of(
                    "status", "✅ started",
                    "interface", nifName
            ));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Stop capture on one interface
     */
    @PostMapping("/stop/{nifName}")
    public ResponseEntity<?> stopOne(@PathVariable String nifName) {
        captureService.stopCaptureOnInterface(nifName);
        return ResponseEntity.ok(Map.of(
                "status", "🛑 stopped",
                "interface", nifName
        ));
    }

    /**
     * Stop capture on all interfaces
     */
    @PostMapping("/stop/all")
    public ResponseEntity<?> stopAll() {
        captureService.stopAllCaptures();
        return ResponseEntity.ok(Map.of(
                "status", "🛑 stopped all"
        ));
    }

    /**
     * Read packets from a pcap file
     */
    @PostMapping("/read")
    public ResponseEntity<?> readFile(@RequestParam String filePath) {
        try {
            captureService.readPcapFile(filePath, this::handlePacket);
            return ResponseEntity.ok(Map.of(
                    "status", "📂 finished reading",
                    "file", filePath
            ));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * List all interfaces in a JSON-friendly format
     */
    @GetMapping("/interfaces")
    public ResponseEntity<?> listInterfaces() {
        try {
            List<Map<String, String>> interfaces = Pcaps.findAllDevs().stream()
                    .map(nif -> Map.of(
                            "name", nif.getName(),
                            "description", nif.getDescription() != null ? nif.getDescription() : "N/A"
                    ))
                    .collect(Collectors.toList());
            return ResponseEntity.ok(interfaces);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Packet handler: You can enrich this to parse & push to DB/Kafka
     */
    private void handlePacket(Packet packet) {
        System.out.println("📦 Packet: " + packet);
        // Example: Extract protocol info here for DB/Kafka pipeline
    }
}
