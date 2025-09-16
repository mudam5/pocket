package com.yourorg.netanalysis.store.repository;

import com.yourorg.netanalysis.store.entities.PacketEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PacketRepository extends JpaRepository<PacketEntity, Long> {
}
