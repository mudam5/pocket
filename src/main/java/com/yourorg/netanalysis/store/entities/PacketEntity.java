package com.yourorg.netanalysis.store.entities;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "packets")
public class PacketEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long id;

    public Instant timestamp;
    public String srcIp;
    public String dstIp;
    public Integer srcPort;
    public Integer dstPort;
    public String protocol;
    public Integer ipLen;
}
