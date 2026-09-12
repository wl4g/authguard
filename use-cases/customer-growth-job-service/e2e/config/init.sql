DROP TABLE IF EXISTS customer_growth_jobs;

CREATE TABLE customer_growth_jobs (
    id BIGINT PRIMARY KEY,
    region VARCHAR(32) NOT NULL,
    tenant_id VARCHAR(128) NOT NULL,
    workspace_id VARCHAR(128) NOT NULL,
    project_id VARCHAR(128) NOT NULL,
    job_id VARCHAR(128) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL,
    owner_user_id VARCHAR(128) NOT NULL,
    UNIQUE (region, tenant_id, workspace_id, project_id, job_id)
);

INSERT INTO customer_growth_jobs (
    id, region, tenant_id, workspace_id, project_id, job_id,
    display_name, status, owner_user_id
) VALUES
    (1, 'global', 'example-corp', 'customer-insights', 'retention-analytics', 'daily-churn-risk-score', 'Daily churn risk scoring', 'READY', 'growth-analyst'),
    (2, 'global', 'example-corp', 'customer-insights', 'retention-analytics', 'vip-retention-risk-audit', 'VIP retention risk audit', 'READY', 'data-scientist'),
    (3, 'global', 'example-corp', 'customer-insights', 'lifetime-value-forecasting', 'daily-customer-lifetime-value-forecast', 'Daily customer lifetime value forecast', 'READY', 'lifecycle-analyst'),
    (4, 'global', 'example-corp', 'campaign-analytics', 'campaign-attribution', 'daily-channel-attribution', 'Daily channel attribution', 'READY', 'marketing-analyst'),
    (5, 'global', 'partner-corp', 'customer-insights', 'retention-analytics', 'daily-churn-risk-score', 'Partner tenant churn risk scoring', 'READY', 'partner-analyst'),
    (6, 'global', 'example-corp', 'customer-insights', 'retention-analytics', 'weekly-retention-cohort-report', 'Weekly retention cohort report', 'PAUSED', 'growth-analyst');
