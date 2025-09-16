package com.yourorg.netanalysis.flow;

import java.time.Instant;

public class Flow {
    public final String key;
    public Instant start;
    public Instant lastSeen;
    public int pktCount;
    public long byteCount;

    public Flow(String key, Instant now) {
        this.key = key;
        this.start = now;
        this.lastSeen = now;
        this.pktCount = 0;
        this.byteCount = 0;
    }

    public void addPacket(int ipLen) {
        this.pktCount++;
        this.byteCount += (ipLen > 0 ? ipLen : 0);
        this.lastSeen = Instant.now();
    }
}
