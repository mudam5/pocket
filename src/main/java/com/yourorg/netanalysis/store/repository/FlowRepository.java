package com.yourorg.netanalysis.store.repository;

import com.yourorg.netanalysis.store.entities.FlowEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface FlowRepository extends JpaRepository<FlowEntity, Long> {
}
