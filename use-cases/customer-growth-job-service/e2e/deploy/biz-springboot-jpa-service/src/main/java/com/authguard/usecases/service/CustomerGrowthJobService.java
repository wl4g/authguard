package com.authguard.usecases.service;

import com.authguard.adapter.model.AuthguardTypes.SqlScope;
import com.authguard.adapter.util.AuthguardUtils;
import com.authguard.usecases.authorization.CustomerGrowthJobResourceMappings;
import com.authguard.usecases.dto.CustomerGrowthJobDto;
import com.authguard.usecases.dto.CustomerGrowthJobSearchRequest;
import com.authguard.usecases.dto.CreateCustomerGrowthJobRequest;
import com.authguard.usecases.dto.UpdateCustomerGrowthJobRequest;
import com.authguard.usecases.entity.CustomerGrowthJobEntity;
import com.authguard.usecases.repository.CustomerGrowthJobJpaRepository;
import com.authguard.usecases.repository.CustomerGrowthJobQueryCriteria;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Service;

@Service
public class CustomerGrowthJobService {
  private final CustomerGrowthJobJpaRepository repository;

  public CustomerGrowthJobService(CustomerGrowthJobJpaRepository repository) {
    this.repository = repository;
  }

  public CustomerGrowthJobDto createJob(CreateCustomerGrowthJobRequest request) {
    SqlScope scope = scopeForAction(CustomerGrowthJobResourceMappings.ACTION_CREATE);
    CustomerGrowthJobEntity job = toEntity(request);
    if (!repository.isCandidateVisible(scope, job)) {
      throw new IllegalArgumentException("Customer growth job not found or not authorized: " + job.id());
    }
    return toDto(repository.create(job));
  }

  public Optional<CustomerGrowthJobDto> getJob(Long id) {
    return repository
        .findByIdVisible(scopeForAction(CustomerGrowthJobResourceMappings.ACTION_READ), id)
        .map(this::toDto);
  }

  public CustomerGrowthJobDto updateJob(Long id, UpdateCustomerGrowthJobRequest request) {
    SqlScope scope = scopeForAction(CustomerGrowthJobResourceMappings.ACTION_UPDATE);
    CustomerGrowthJobEntity existing =
        repository
            .findByIdVisible(scope, id)
            .orElseThrow(
                () ->
                    new IllegalArgumentException(
                        "Customer growth job not found or not authorized: " + id));
    CustomerGrowthJobEntity updated =
        new CustomerGrowthJobEntity(
            existing.id(),
            existing.region(),
            existing.tenantId(),
            existing.workspaceId(),
            existing.projectId(),
            existing.jobId(),
            request.displayName(),
            request.status(),
            request.ownerUserId());
    return toDto(repository.updateVisible(scope, updated));
  }

  public void deleteJob(Long id) {
    repository.deleteByIdVisible(scopeForAction(CustomerGrowthJobResourceMappings.ACTION_DELETE), id);
  }

  public List<CustomerGrowthJobDto> listVisibleJobs(CustomerGrowthJobSearchRequest request) {
    SqlScope scope = scopeForAction(CustomerGrowthJobResourceMappings.ACTION_READ);
    CustomerGrowthJobQueryCriteria criteria =
        new CustomerGrowthJobQueryCriteria(
            request.workspaceId(), request.projectId(), request.status(), request.ownerUserId());
    return repository.findVisibleJobs(scope, criteria).stream().map(this::toDto).toList();
  }

  private SqlScope scopeForAction(String action) {
    return AuthguardUtils.currentScopeForAction(
        action, CustomerGrowthJobResourceMappings.customerGrowthJob());
  }

  private CustomerGrowthJobEntity toEntity(CreateCustomerGrowthJobRequest request) {
    return new CustomerGrowthJobEntity(
        request.id(),
        request.region(),
        request.tenantId(),
        request.workspaceId(),
        request.projectId(),
        request.jobId(),
        request.displayName(),
        request.status(),
        request.ownerUserId());
  }

  private CustomerGrowthJobDto toDto(CustomerGrowthJobEntity job) {
    return new CustomerGrowthJobDto(
        job.id(),
        job.region(),
        job.tenantId(),
        job.workspaceId(),
        job.projectId(),
        job.jobId(),
        job.displayName(),
        job.status(),
        job.ownerUserId());
  }
}
