
use super::*;

#[test]
fn combines_network_transport_and_subject_conditions() {
    let conditions = AuthorizationConditionSpec {
        source_ip: Some(SourceIpConditionSpec {
            in_cidr: vec!["10.0.0.0/8".to_string()],
            not_in_cidr: vec!["10.20.0.0/16".to_string()],
        }),
        request: RequestConditionSpec {
            methods: vec!["GET".to_string()],
            secure_transport: Some(true),
        },
        subject: SubjectConditionSpec {
            mfa: Some(true),
            claims: BTreeMap::from([("department".to_string(), "risk".to_string())]),
        },
    }
    .compile()
    .expect("conditions");
    let context = EvaluationContext {
        source_ip: Some("10.10.1.8".parse().expect("ip")),
        request_method: Some("get".to_string()),
        secure_transport: Some(true),
        claims: BTreeMap::from([
            ("mfa".to_string(), "true".to_string()),
            ("department".to_string(), "risk".to_string()),
        ]),
    };
    assert!(conditions.matches(&context));
}

#[test]
fn required_attributes_fail_closed() {
    let conditions = AuthorizationConditionSpec {
        source_ip: Some(SourceIpConditionSpec {
            in_cidr: vec!["10.0.0.0/8".to_string()],
            not_in_cidr: Vec::new(),
        }),
        request: RequestConditionSpec { methods: Vec::new(), secure_transport: Some(true) },
        subject: SubjectConditionSpec { mfa: Some(true), claims: BTreeMap::new() },
    }
    .compile()
    .expect("conditions");
    assert!(!conditions.matches(&EvaluationContext::default()));
}
