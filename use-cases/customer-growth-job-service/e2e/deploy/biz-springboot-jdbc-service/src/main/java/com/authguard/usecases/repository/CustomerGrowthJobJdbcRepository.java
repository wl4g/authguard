package com.authguard.usecases.repository;

import com.authguard.adapter.model.AuthguardTypes.SqlScope;
import com.authguard.usecases.entity.CustomerGrowthJobEntity;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

@Repository
public class CustomerGrowthJobJdbcRepository {
  private static final RowMapper<CustomerGrowthJobEntity> ROW_MAPPER =
      (rs, rowNum) ->
          new CustomerGrowthJobEntity(
              rs.getLong("id"),
              rs.getString("region"),
              rs.getString("tenant_id"),
              rs.getString("workspace_id"),
              rs.getString("project_id"),
              rs.getString("job_id"),
              rs.getString("display_name"),
              rs.getString("status"),
              rs.getString("owner_user_id"));

  private final JdbcTemplate jdbcTemplate;

  public CustomerGrowthJobJdbcRepository(JdbcTemplate jdbcTemplate) {
    this.jdbcTemplate = jdbcTemplate;
  }

  public CustomerGrowthJobEntity create(CustomerGrowthJobEntity job) {
    jdbcTemplate.update(
        "INSERT INTO e2e_authguard_customer_growth_jobs(id, region, tenant_id, workspace_id, project_id, job_id, display_name, status, owner_user_id) "
            + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        job.id(),
        job.region(),
        job.tenantId(),
        job.workspaceId(),
        job.projectId(),
        job.jobId(),
        job.displayName(),
        job.status(),
        job.ownerUserId());
    return job;
  }

  public Optional<CustomerGrowthJobEntity> findByIdVisible(SqlScope scope, Long id) {
    List<Object> args = new ArrayList<>();
    args.add(id);
    args.addAll(scope.args());
    List<CustomerGrowthJobEntity> rows =
        jdbcTemplate.query(
            "SELECT * FROM e2e_authguard_customer_growth_jobs WHERE id = ? AND (" + scope.where() + ")",
            ROW_MAPPER,
            args.toArray());
    return rows.stream().findFirst();
  }

  public CustomerGrowthJobEntity updateVisible(SqlScope scope, CustomerGrowthJobEntity job) {
    List<Object> args = new ArrayList<>();
    args.add(job.displayName());
    args.add(job.status());
    args.add(job.ownerUserId());
    args.add(job.id());
    args.addAll(scope.args());
    int affected =
        jdbcTemplate.update(
            "UPDATE e2e_authguard_customer_growth_jobs SET display_name = ?, status = ?, owner_user_id = ? "
                + "WHERE id = ? AND ("
                + scope.where()
                + ")",
            args.toArray());
    requireAffected(affected, job.id());
    return job;
  }

  public void deleteByIdVisible(SqlScope scope, Long id) {
    List<Object> args = new ArrayList<>();
    args.add(id);
    args.addAll(scope.args());
    int affected =
        jdbcTemplate.update(
            "DELETE FROM e2e_authguard_customer_growth_jobs WHERE id = ? AND (" + scope.where() + ")",
            args.toArray());
    requireAffected(affected, id);
  }

  public boolean isCandidateVisible(SqlScope scope, CustomerGrowthJobEntity job) {
    List<Object> args = new ArrayList<>();
    args.add(job.region());
    args.add(job.tenantId());
    args.add(job.workspaceId());
    args.add(job.projectId());
    args.add(job.jobId());
    args.addAll(scope.args());
    Integer count =
        jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM ("
                + "SELECT CAST(? AS VARCHAR(32)) AS region, "
                + "CAST(? AS VARCHAR(128)) AS tenant_id, "
                + "CAST(? AS VARCHAR(128)) AS workspace_id, "
                + "CAST(? AS VARCHAR(128)) AS project_id, "
                + "CAST(? AS VARCHAR(128)) AS job_id"
                + ") candidate WHERE "
                + scope.where(),
            Integer.class,
            args.toArray());
    return Integer.valueOf(1).equals(count);
  }

  public List<CustomerGrowthJobEntity> findVisibleJobs(SqlScope scope, CustomerGrowthJobQueryCriteria criteria) {
    List<String> clauses = new ArrayList<>();
    List<Object> args = new ArrayList<>(scope.args());
    clauses.add(scope.where());
    addEquals(clauses, args, "workspace_id", criteria.workspaceId());
    addEquals(clauses, args, "project_id", criteria.projectId());
    addEquals(clauses, args, "status", criteria.status());
    addEquals(clauses, args, "owner_user_id", criteria.ownerUserId());

    return jdbcTemplate.query(
        "SELECT * FROM e2e_authguard_customer_growth_jobs WHERE "
            + String.join(" AND ", clauses)
            + " ORDER BY region, tenant_id, workspace_id, project_id, job_id",
        ROW_MAPPER,
        args.toArray());
  }

  private static void addEquals(List<String> clauses, List<Object> args, String column, String value) {
    if (value == null || value.isBlank()) {
      return;
    }
    clauses.add(column + " = ?");
    args.add(value);
  }

  private static void requireAffected(int affected, Long id) {
    if (affected == 0) {
      throw new IllegalArgumentException("Customer growth job not found or not authorized: " + id);
    }
  }
}
