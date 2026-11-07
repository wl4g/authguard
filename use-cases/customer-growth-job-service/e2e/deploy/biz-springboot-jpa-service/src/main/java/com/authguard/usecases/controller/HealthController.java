package com.authguard.usecases.controller;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HealthController {
  @PersistenceContext private EntityManager entityManager;

  @GetMapping("/healthz")
  public String health() {
    entityManager.createNativeQuery("SELECT 1").getSingleResult();
    return "ok";
  }
}
