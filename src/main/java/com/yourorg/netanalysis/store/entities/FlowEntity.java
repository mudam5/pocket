package com.yourorg.netanalysis.store.entities;

import jakarta.persistence.*;

@Entity
@Table(name = "flows")
public class FlowEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long id;
    public String flowKey;
    public Integer pktCount;
    public Long byteCount;
}
