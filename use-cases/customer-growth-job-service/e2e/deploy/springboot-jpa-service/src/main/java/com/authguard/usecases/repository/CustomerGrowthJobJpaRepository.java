package com.authguard.usecases.repository;

import com.authguard.adapter.model.AuthguardTypes.SqlScope;
import com.authguard.usecases.entity.CustomerGrowthJobEntity;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Query;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public class CustomerGrowthJobJpaRepository {
  @PersistenceContext private EntityManager entityManager;

  @Transactional
  public CustomerGrowthJobEntity create(CustomerGrowthJobEntity job) {
    entityManager.persist(job);
    return job;
  }

  public Optional<CustomerGrowthJobEntity> findByIdVisible(SqlScope scope, Long id) {
    Query query =
        entityManager.createNativeQuery(
            "SELECT * FROM customer_growth_jobs WHERE id = ? AND (" + scope.where() + ")",
            CustomerGrowthJobEntity.class);
    query.setParameter(1, id);
    bind(query, scope.args(), 2);
    query.setMaxResults(1);
    @SuppressWarnings("unchecked")
    List<CustomerGrowthJobEntity> jobs = query.getResultList();
    return jobs.stream().findFirst();
  }

  @Transactional
  public CustomerGrowthJobEntity updateVisible(SqlScope scope, CustomerGrowthJobEntity job) {
    Query query =
        entityManager.createNativeQuery(
            "UPDATE customer_growth_jobs SET display_name = ?, status = ?, owner_user_id = ? "
                + "WHERE id = ? AND ("
                + scope.where()
                + ")");
    query.setParameter(1, job.displayName());
    query.setParameter(2, job.status());
    query.setParameter(3, job.ownerUserId());
    query.setParameter(4, job.id());
    bind(query, scope.args(), 5);
    requireAffected(query.executeUpdate(), job.id());
    entityManager.clear();
    return job;
  }

  @Transactional
  public void deleteByIdVisible(SqlScope scope, Long id) {
    Query query =
        entityManager.createNativeQuery(
            "DELETE FROM customer_growth_jobs WHERE id = ? AND (" + scope.where() + ")");
    query.setParameter(1, id);
    bind(query, scope.args(), 2);
    requireAffected(query.executeUpdate(), id);
    entityManager.clear();
  }

  public boolean isCandidateVisible(SqlScope scope, CustomerGrowthJobEntity job) {
    Query query =
        entityManager.createNativeQuery(
            "SELECT COUNT(*) FROM ("
                + "SELECT CAST(? AS VARCHAR(32)) AS region, "
                + "CAST(? AS VARCHAR(128)) AS tenant_id, "
                + "CAST(? AS VARCHAR(128)) AS workspace_id, "
                + "CAST(? AS VARCHAR(128)) AS project_id, "
                + "CAST(? AS VARCHAR(128)) AS job_id"
                + ") candidate WHERE "
                + scope.where());
    query.setParameter(1, job.region());
    query.setParameter(2, job.tenantId());
    query.setParameter(3, job.workspaceId());
    query.setParameter(4, job.projectId());
    query.setParameter(5, job.jobId());
    bind(query, scope.args(), 6);
    return ((Number) query.getSingleResult()).longValue() == 1;
  }

  public List<CustomerGrowthJobEntity> findVisibleJobs(SqlScope scope, CustomerGrowthJobQueryCriteria criteria) {
    List<String> clauses = new ArrayList<>();
    List<String> args = new ArrayList<>(scope.args());
    clauses.add(scope.where());
    addEquals(clauses, args, "workspace_id", criteria.workspaceId());
    addEquals(clauses, args, "project_id", criteria.projectId());
    addEquals(clauses, args, "status", criteria.status());
    addEquals(clauses, args, "owner_user_id", criteria.ownerUserId());

    Query query =
        entityManager.createNativeQuery(
            "SELECT id, region, tenant_id, workspace_id, project_id, job_id "
                + ", display_name, status, owner_user_id "
                + "FROM customer_growth_jobs WHERE "
                + String.join(" AND ", clauses)
                + " ORDER BY region, tenant_id, workspace_id, project_id, job_id",
            CustomerGrowthJobEntity.class);
    bind(query, args, 1);
    @SuppressWarnings("unchecked")
    List<CustomerGrowthJobEntity> jobs = query.getResultList();
    return jobs;
  }

  private static void addEquals(List<String> clauses, List<String> args, String column, String value) {
    if (value == null || value.isBlank()) {
      return;
    }
    clauses.add(column + " = ?");
    args.add(value);
  }

  private static void bind(Query query, List<String> args, int firstPosition) {
    for (int i = 0; i < args.size(); i++) {
      query.setParameter(firstPosition + i, args.get(i));
    }
  }

  private static void requireAffected(int affected, Long id) {
    if (affected == 0) {
      throw new IllegalArgumentException("Customer growth job not found or not authorized: " + id);
    }
  }
}
