package com.yourorg.netanalysis.features;

import com.yourorg.netanalysis.flow.Flow;

public class FeatureExtractor {

    public static double[] extractForFlow(Flow f) {
        double duration = (f.lastSeen.toEpochMilli() - f.start.toEpochMilli()) / 1000.0;
        double pktCount = f.pktCount;
        double byteCount = f.byteCount;
        double avgPktSize = pktCount > 0 ? byteCount / pktCount : 0.0;
        return new double[] { pktCount, byteCount, duration, avgPktSize };
    }
}
