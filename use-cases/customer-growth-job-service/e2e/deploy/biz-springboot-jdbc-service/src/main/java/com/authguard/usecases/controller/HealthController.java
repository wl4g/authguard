package com.authguard.usecases.controller;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HealthController {
  private final JdbcTemplate jdbcTemplate;

  public HealthController(JdbcTemplate jdbcTemplate) {
    this.jdbcTemplate = jdbcTemplate;
  }

  @GetMapping("/healthz")
  public String health() {
    jdbcTemplate.queryForObject("SELECT 1", Integer.class);
    return "ok";
  }
}
