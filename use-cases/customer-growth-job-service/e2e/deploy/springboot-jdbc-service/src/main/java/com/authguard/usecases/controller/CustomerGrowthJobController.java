package com.authguard.usecases.controller;

import com.authguard.usecases.dto.CustomerGrowthJobDto;
import com.authguard.usecases.dto.CustomerGrowthJobSearchRequest;
import com.authguard.usecases.dto.CreateCustomerGrowthJobRequest;
import com.authguard.usecases.dto.UpdateCustomerGrowthJobRequest;
import com.authguard.usecases.service.CustomerGrowthJobService;
import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/customer-growth/jobs")
public class CustomerGrowthJobController {
  private final CustomerGrowthJobService service;

  public CustomerGrowthJobController(CustomerGrowthJobService service) {
    this.service = service;
  }

  @PostMapping
  public CustomerGrowthJobDto createJob(@RequestBody CreateCustomerGrowthJobRequest request) {
    return service.createJob(request);
  }

  @GetMapping("/{id}")
  public ResponseEntity<CustomerGrowthJobDto> getJob(@PathVariable("id") Long id) {
    return service.getJob(id).map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
  }

  @PutMapping("/{id}")
  public CustomerGrowthJobDto updateJob(
      @PathVariable("id") Long id, @RequestBody UpdateCustomerGrowthJobRequest request) {
    return service.updateJob(id, request);
  }

  @DeleteMapping("/{id}")
  public ResponseEntity<Void> deleteJob(@PathVariable("id") Long id) {
    service.deleteJob(id);
    return ResponseEntity.noContent().build();
  }

  @GetMapping
  public List<CustomerGrowthJobDto> listVisibleJobs(
      @RequestParam(name = "workspace_id", required = false) String workspaceId,
      @RequestParam(name = "project_id", required = false) String projectId,
      @RequestParam(name = "status", required = false) String status,
      @RequestParam(name = "owner_user_id", required = false) String ownerUserId) {
    return service.listVisibleJobs(
        new CustomerGrowthJobSearchRequest(workspaceId, projectId, status, ownerUserId));
  }
}
