use authguard_core::model::{PathMap, ResourceSqlMapping, SegmentMap};
use rusqlite::{params_from_iter, Connection};

type DocumentScenario<'a> = (&'a str, Vec<&'a str>, Vec<&'a str>, Vec<&'a str>);

fn setup_documents() -> Connection {
    let conn = Connection::open_in_memory().expect("sqlite");
    conn.execute(
        "CREATE TABLE documents(workspace_id TEXT NOT NULL, document_id TEXT NOT NULL)",
        [],
    )
    .unwrap();
    for (workspace_id, document_id) in [
        ("default", "security-autonomy-fixer"),
        ("default", "payment-risk-fixer"),
        ("default", "payroll-fixer"),
        ("security", "security-autonomy-fixer"),
        ("security", "bot-fixer"),
        ("risk", "fraud-fixer"),
    ] {
        conn.execute(
            "INSERT INTO documents(workspace_id, document_id) VALUES (?, ?)",
            [workspace_id, document_id],
        )
        .unwrap();
    }
    conn
}

fn query_documents(conn: &Connection, allow: &[&str], deny: &[&str]) -> Vec<String> {
    let scope = document_mapping().compile_scope_strs(allow, deny).unwrap();
    let sql = format!(
        "SELECT workspace_id || '/' || document_id FROM documents WHERE {} ORDER BY 1",
        scope.where_clause
    );
    let mut stmt = conn.prepare(&sql).unwrap();
    stmt.query_map(params_from_iter(scope.params), |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

#[test]
fn document_sql_scope_scenarios() {
    let conn = setup_documents();
    let all = vec![
        "default/payment-risk-fixer",
        "default/payroll-fixer",
        "default/security-autonomy-fixer",
        "risk/fraud-fixer",
        "security/bot-fixer",
        "security/security-autonomy-fixer",
    ];
    let default_all = vec![
        "default/payment-risk-fixer",
        "default/payroll-fixer",
        "default/security-autonomy-fixer",
    ];
    let security_all = vec!["security/bot-fixer", "security/security-autonomy-fixer"];

    let scenarios: Vec<DocumentScenario<'_>> = vec![
        (
            "exact default security fixer",
            vec!["urn:iam:prod:documents:global:default:document/security-autonomy-fixer"],
            vec![],
            vec!["default/security-autonomy-fixer"],
        ),
        (
            "default workspace_id wildcard",
            vec!["urn:iam:prod:documents:global:default:document/*"],
            vec![],
            default_all.clone(),
        ),
        (
            "security workspace_id wildcard",
            vec!["urn:iam:prod:documents:global:security:document/*"],
            vec![],
            security_all.clone(),
        ),
        (
            "tenant wildcard",
            vec!["urn:iam:prod:documents:global:*:document/*"],
            vec![],
            all.clone(),
        ),
        (
            "service wildcard exact",
            vec!["urn:iam:prod:*:global:default:document/security-autonomy-fixer"],
            vec![],
            vec!["default/security-autonomy-fixer"],
        ),
        (
            "partition wildcard exact",
            vec!["urn:iam:*:documents:global:default:document/payment-risk-fixer"],
            vec![],
            vec!["default/payment-risk-fixer"],
        ),
        (
            "region wildcard default all",
            vec!["urn:iam:prod:documents:*:default:document/*"],
            vec![],
            default_all.clone(),
        ),
        (
            "globstar default all",
            vec!["urn:iam:prod:documents:global:default:**"],
            vec![],
            default_all.clone(),
        ),
        ("globstar platform all", vec!["urn:iam:prod:documents:global:*:**"], vec![], all.clone()),
        (
            "allow default deny payroll",
            vec!["urn:iam:prod:documents:global:default:document/*"],
            vec!["urn:iam:prod:documents:global:default:document/payroll-fixer"],
            vec!["default/payment-risk-fixer", "default/security-autonomy-fixer"],
        ),
        (
            "allow all deny security workspace_id",
            vec!["urn:iam:prod:documents:global:*:document/*"],
            vec!["urn:iam:prod:documents:global:security:document/*"],
            vec![
                "default/payment-risk-fixer",
                "default/payroll-fixer",
                "default/security-autonomy-fixer",
                "risk/fraud-fixer",
            ],
        ),
        (
            "allow security deny bot",
            vec!["urn:iam:prod:documents:global:security:document/*"],
            vec!["urn:iam:prod:documents:global:security:document/bot-fixer"],
            vec!["security/security-autonomy-fixer"],
        ),
        (
            "two exact allows",
            vec![
                "urn:iam:prod:documents:global:default:document/security-autonomy-fixer",
                "urn:iam:prod:documents:global:security:document/bot-fixer",
            ],
            vec![],
            vec!["default/security-autonomy-fixer", "security/bot-fixer"],
        ),
        (
            "two workspace_id allows",
            vec![
                "urn:iam:prod:documents:global:default:document/*",
                "urn:iam:prod:documents:global:risk:document/*",
            ],
            vec![],
            vec![
                "default/payment-risk-fixer",
                "default/payroll-fixer",
                "default/security-autonomy-fixer",
                "risk/fraud-fixer",
            ],
        ),
        (
            "deny without allow denies all",
            vec![],
            vec!["urn:iam:prod:documents:global:default:document/*"],
            vec![],
        ),
        (
            "non matching service",
            vec!["urn:iam:prod:github:global:default:document/*"],
            vec![],
            vec![],
        ),
        (
            "non matching path type",
            vec!["urn:iam:prod:documents:global:default:repo/*"],
            vec![],
            vec![],
        ),
        (
            "non matching region",
            vec!["urn:iam:prod:documents:us-west-2:default:document/*"],
            vec![],
            vec![],
        ),
        (
            "exact missing resource",
            vec!["urn:iam:prod:documents:global:default:document/missing"],
            vec![],
            vec![],
        ),
        (
            "allow all deny all",
            vec!["urn:iam:prod:documents:global:*:document/*"],
            vec!["urn:iam:prod:documents:global:*:document/*"],
            vec![],
        ),
        (
            "allow exact deny same exact",
            vec!["urn:iam:prod:documents:global:default:document/payroll-fixer"],
            vec!["urn:iam:prod:documents:global:default:document/payroll-fixer"],
            vec![],
        ),
        (
            "deny nonexistent does not change allow",
            vec!["urn:iam:prod:documents:global:default:document/*"],
            vec!["urn:iam:prod:documents:global:default:document/nope"],
            default_all.clone(),
        ),
        (
            "allow all deny default",
            vec!["urn:iam:prod:documents:global:*:document/*"],
            vec!["urn:iam:prod:documents:global:default:document/*"],
            vec!["risk/fraud-fixer", "security/bot-fixer", "security/security-autonomy-fixer"],
        ),
        (
            "risk workspace_id exact",
            vec!["urn:iam:prod:documents:global:risk:document/fraud-fixer"],
            vec![],
            vec!["risk/fraud-fixer"],
        ),
        (
            "path first segment wildcard",
            vec!["urn:iam:prod:documents:global:*:*/security-autonomy-fixer"],
            vec![],
            vec!["default/security-autonomy-fixer", "security/security-autonomy-fixer"],
        ),
        (
            "document_id wildcard all tenants",
            vec!["urn:iam:prod:documents:global:*:document/*"],
            vec![],
            all.clone(),
        ),
        (
            "all colon wildcards exact path",
            vec!["urn:iam:*:*:*:*:document/security-autonomy-fixer"],
            vec![],
            vec!["default/security-autonomy-fixer", "security/security-autonomy-fixer"],
        ),
        (
            "trailing globstar after literal",
            vec!["urn:iam:prod:documents:global:default:document/**"],
            vec![],
            default_all.clone(),
        ),
        ("star star path", vec!["urn:iam:prod:documents:global:*:*/*"], vec![], all.clone()),
        (
            "allow default and security deny default payment",
            vec![
                "urn:iam:prod:documents:global:default:document/*",
                "urn:iam:prod:documents:global:security:document/*",
            ],
            vec!["urn:iam:prod:documents:global:default:document/payment-risk-fixer"],
            vec![
                "default/payroll-fixer",
                "default/security-autonomy-fixer",
                "security/bot-fixer",
                "security/security-autonomy-fixer",
            ],
        ),
        (
            "allow all deny exact in security",
            vec!["urn:iam:prod:documents:global:*:document/*"],
            vec!["urn:iam:prod:documents:global:security:document/security-autonomy-fixer"],
            vec![
                "default/payment-risk-fixer",
                "default/payroll-fixer",
                "default/security-autonomy-fixer",
                "risk/fraud-fixer",
                "security/bot-fixer",
            ],
        ),
        (
            "tenant globstar risk",
            vec!["urn:iam:prod:documents:global:risk:**"],
            vec![],
            vec!["risk/fraud-fixer"],
        ),
    ];

    assert!(scenarios.len() >= 30);
    for (document_id, allow, deny, expected) in scenarios {
        let actual = query_documents(&conn, &allow, &deny);
        assert_eq!(actual, expected, "scenario {document_id}");
    }
}

#[test]
fn s3_object_scope_scenarios() {
    let conn = Connection::open_in_memory().expect("sqlite");
    conn.execute(
        "CREATE TABLE objects(region TEXT, account_id TEXT, bucket TEXT, object_key TEXT)",
        [],
    )
    .unwrap();
    for (region, account, bucket, key) in [
        ("global", "111122223333", "company-audit-logs", "2026/08/22/report.json"),
        ("global", "111122223333", "company-audit-logs", "2026/08/21/report.json"),
        ("us-west-2", "111122223333", "app-data", "tenant-a/state.json"),
        ("us-east-1", "111122223333", "app-data", "tenant-b/state.json"),
        ("global", "999900001111", "company-audit-logs", "2026/08/22/report.json"),
    ] {
        conn.execute(
            "INSERT INTO objects(region, account_id, bucket, object_key) VALUES (?, ?, ?, ?)",
            [region, account, bucket, key],
        )
        .unwrap();
    }

    let query = |allow: &[&str], deny: &[&str]| -> Vec<String> {
        let scope = s3_object_mapping().compile_scope_strs(allow, deny).unwrap();
        let sql = format!("SELECT region || '/' || account_id || '/' || bucket || '/' || object_key FROM objects WHERE {} ORDER BY 1", scope.where_clause);
        let mut stmt = conn.prepare(&sql).unwrap();
        stmt.query_map(params_from_iter(scope.params), |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };

    let cases = vec![
        (
            "exact object",
            vec!["urn:iam:prod:s3:global:111122223333:bucket/company-audit-logs/object/2026/08/22/report.json"],
            vec![],
            vec!["global/111122223333/company-audit-logs/2026/08/22/report.json"],
        ),
        (
            "prefix reports",
            vec!["urn:iam:prod:s3:global:111122223333:bucket/company-audit-logs/object/2026/08/**"],
            vec![],
            vec![
                "global/111122223333/company-audit-logs/2026/08/21/report.json",
                "global/111122223333/company-audit-logs/2026/08/22/report.json",
            ],
        ),
        (
            "region wildcard app data",
            vec!["urn:iam:prod:s3:*:111122223333:bucket/app-data/object/**"],
            vec![],
            vec![
                "us-east-1/111122223333/app-data/tenant-b/state.json",
                "us-west-2/111122223333/app-data/tenant-a/state.json",
            ],
        ),
        (
            "deny one prefix",
            vec!["urn:iam:prod:s3:*:111122223333:bucket/app-data/object/**"],
            vec!["urn:iam:prod:s3:us-east-1:111122223333:bucket/app-data/object/**"],
            vec!["us-west-2/111122223333/app-data/tenant-a/state.json"],
        ),
        (
            "account isolation",
            vec!["urn:iam:prod:s3:global:999900001111:bucket/company-audit-logs/object/**"],
            vec![],
            vec!["global/999900001111/company-audit-logs/2026/08/22/report.json"],
        ),
    ];

    for (document_id, allow, deny, expected) in cases {
        assert_eq!(query(&allow, &deny), expected, "scenario {document_id}");
    }
}

fn document_mapping() -> ResourceSqlMapping {
    ResourceSqlMapping {
        partition: SegmentMap::constant("prod"),
        service: SegmentMap::constant("documents"),
        region: SegmentMap::constant("global"),
        tenant: SegmentMap::column("workspace_id"),
        path: vec![PathMap::literal("document"), PathMap::column("document_id")],
    }
}

fn s3_object_mapping() -> ResourceSqlMapping {
    ResourceSqlMapping {
        partition: SegmentMap::constant("prod"),
        service: SegmentMap::constant("s3"),
        region: SegmentMap::column("region"),
        tenant: SegmentMap::column("account_id"),
        path: vec![
            PathMap::literal("bucket"),
            PathMap::column("bucket"),
            PathMap::literal("object"),
            PathMap::remainder_column("object_key"),
        ],
    }
}
