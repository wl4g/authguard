use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{PathPattern, SegmentPattern, UrnPattern};

#[derive(Debug, Error)]
pub enum SqlCompileError {
    #[error("invalid URN pattern: {0}")]
    InvalidPattern(String),
    #[error("pattern is not SQL-pushdown safe for remainder column: {0}")]
    UnsupportedRemainderPattern(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqlScope {
    pub where_clause: String,
    pub params: Vec<String>,
}

impl SqlScope {
    #[must_use]
    pub fn deny_all() -> Self {
        Self { where_clause: "0=1".to_string(), params: Vec::new() }
    }

    #[must_use]
    pub fn allow_all() -> Self {
        Self { where_clause: "1=1".to_string(), params: Vec::new() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SegmentMap {
    Const(String),
    Column(String),
}

impl SegmentMap {
    #[must_use]
    pub fn constant(value: impl Into<String>) -> Self {
        Self::Const(value.into())
    }

    #[must_use]
    pub fn column(name: impl Into<String>) -> Self {
        Self::Column(name.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathMap {
    Literal(String),
    Column(String),
    RemainderColumn(String),
}

impl PathMap {
    #[must_use]
    pub fn literal(value: impl Into<String>) -> Self {
        Self::Literal(value.into())
    }

    #[must_use]
    pub fn column(name: impl Into<String>) -> Self {
        Self::Column(name.into())
    }

    #[must_use]
    pub fn remainder_column(name: impl Into<String>) -> Self {
        Self::RemainderColumn(name.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceSqlMapping {
    pub partition: SegmentMap,
    pub service: SegmentMap,
    pub region: SegmentMap,
    pub tenant: SegmentMap,
    pub path: Vec<PathMap>,
}

impl ResourceSqlMapping {
    /// Compiles allow/deny Resource URN patterns into a SQL `WHERE` fragment.
    ///
    /// # Errors
    ///
    /// Returns [`SqlCompileError::UnsupportedRemainderPattern`] when a pattern
    /// cannot be represented safely by this table mapping, for example a
    /// wildcard inside a remainder column.
    pub fn compile_scope(
        &self,
        allow: &[UrnPattern],
        deny: &[UrnPattern],
    ) -> Result<SqlScope, SqlCompileError> {
        let mut allow_scopes = Vec::new();
        for pattern in allow {
            if let Some(scope) = self.compile_pattern(pattern)? {
                allow_scopes.push(scope);
            }
        }

        if allow_scopes.is_empty() {
            return Ok(SqlScope::deny_all());
        }

        let mut scope = or_scopes(&allow_scopes);
        for pattern in deny {
            if let Some(deny_scope) = self.compile_pattern(pattern)? {
                if deny_scope.where_clause == "1=1" {
                    return Ok(SqlScope::deny_all());
                }
                scope.where_clause =
                    format!("({}) AND NOT ({})", scope.where_clause, deny_scope.where_clause);
                scope.params.extend(deny_scope.params);
            }
        }
        Ok(scope)
    }

    /// Parses string patterns and compiles them into a SQL `WHERE` fragment.
    ///
    /// # Errors
    ///
    /// Returns [`SqlCompileError::InvalidPattern`] for malformed URNs and
    /// [`SqlCompileError::UnsupportedRemainderPattern`] for patterns that cannot
    /// be pushed down safely.
    pub fn compile_scope_strs(
        &self,
        allow: &[&str],
        deny: &[&str],
    ) -> Result<SqlScope, SqlCompileError> {
        let allow = parse_patterns(allow)?;
        let deny = parse_patterns(deny)?;
        self.compile_scope(&allow, &deny)
    }

    fn compile_pattern(&self, pattern: &UrnPattern) -> Result<Option<SqlScope>, SqlCompileError> {
        let mut clauses = Vec::new();
        let mut params = Vec::new();

        if !compile_segment(&self.partition, &pattern.partition, &mut clauses, &mut params) {
            return Ok(None);
        }
        if !compile_segment(&self.service, &pattern.service, &mut clauses, &mut params) {
            return Ok(None);
        }
        if !compile_segment(&self.region, &pattern.region, &mut clauses, &mut params) {
            return Ok(None);
        }
        if !compile_segment(&self.tenant, &pattern.tenant, &mut clauses, &mut params) {
            return Ok(None);
        }
        if !self.compile_path(&pattern.path, &mut clauses, &mut params)? {
            return Ok(None);
        }

        if clauses.is_empty() {
            Ok(Some(SqlScope::allow_all()))
        } else {
            Ok(Some(SqlScope { where_clause: clauses.join(" AND "), params }))
        }
    }

    fn compile_path(
        &self,
        pattern: &[PathPattern],
        clauses: &mut Vec<String>,
        params: &mut Vec<String>,
    ) -> Result<bool, SqlCompileError> {
        let mut pidx = 0usize;
        for mapping in &self.path {
            if matches!(pattern.get(pidx), Some(PathPattern::GlobStar)) {
                return Ok(true);
            }
            match mapping {
                PathMap::Literal(expected) => {
                    let Some(segment) = pattern.get(pidx) else {
                        return Ok(false);
                    };
                    match segment {
                        PathPattern::Exact(value) if value == expected => {}
                        PathPattern::Any => {}
                        PathPattern::Exact(_) => return Ok(false),
                        PathPattern::GlobStar => return Ok(true),
                    }
                    pidx += 1;
                }
                PathMap::Column(column) => {
                    let Some(segment) = pattern.get(pidx) else {
                        return Ok(false);
                    };
                    match segment {
                        PathPattern::Exact(value) => {
                            clauses.push(format!("{column} = ?"));
                            params.push(value.clone());
                        }
                        PathPattern::Any => {}
                        PathPattern::GlobStar => return Ok(true),
                    }
                    pidx += 1;
                }
                PathMap::RemainderColumn(column) => {
                    let remaining = &pattern[pidx..];
                    compile_remainder(column, remaining, clauses, params)?;
                    pidx = pattern.len();
                    break;
                }
            }
        }

        if pidx == pattern.len() || pattern[pidx..] == [PathPattern::GlobStar] {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

fn parse_patterns(patterns: &[&str]) -> Result<Vec<UrnPattern>, SqlCompileError> {
    patterns
        .iter()
        .map(|pattern| {
            UrnPattern::from_str(pattern)
                .map_err(|err| SqlCompileError::InvalidPattern(err.to_string()))
        })
        .collect()
}

fn compile_segment(
    mapping: &SegmentMap,
    pattern: &SegmentPattern,
    clauses: &mut Vec<String>,
    params: &mut Vec<String>,
) -> bool {
    match (mapping, pattern) {
        (_, SegmentPattern::Any) => true,
        (SegmentMap::Const(expected), SegmentPattern::Exact(value)) => expected == value,
        (SegmentMap::Column(column), SegmentPattern::Exact(value)) => {
            clauses.push(format!("{column} = ?"));
            params.push(value.clone());
            true
        }
    }
}

fn compile_remainder(
    column: &str,
    remaining: &[PathPattern],
    clauses: &mut Vec<String>,
    params: &mut Vec<String>,
) -> Result<(), SqlCompileError> {
    if remaining.is_empty() {
        return Ok(());
    }
    if remaining == [PathPattern::GlobStar] {
        return Ok(());
    }
    if remaining.iter().any(|segment| matches!(segment, PathPattern::Any)) {
        return Err(SqlCompileError::UnsupportedRemainderPattern(format!("{remaining:?}")));
    }
    if matches!(remaining.last(), Some(PathPattern::GlobStar)) {
        let prefix = remaining[..remaining.len() - 1]
            .iter()
            .map(|segment| match segment {
                PathPattern::Exact(value) => Ok(value.as_str()),
                _ => Err(SqlCompileError::UnsupportedRemainderPattern(format!("{remaining:?}"))),
            })
            .collect::<Result<Vec<_>, _>>()?
            .join("/");
        if !prefix.is_empty() {
            clauses.push(format!("({column} = ? OR {column} LIKE ?)"));
            params.push(prefix.clone());
            params.push(format!("{prefix}/%"));
        }
        return Ok(());
    }

    let exact = remaining
        .iter()
        .map(|segment| match segment {
            PathPattern::Exact(value) => Ok(value.as_str()),
            _ => Err(SqlCompileError::UnsupportedRemainderPattern(format!("{remaining:?}"))),
        })
        .collect::<Result<Vec<_>, _>>()?
        .join("/");
    clauses.push(format!("{column} = ?"));
    params.push(exact);
    Ok(())
}

fn or_scopes(scopes: &[SqlScope]) -> SqlScope {
    if scopes.len() == 1 {
        return scopes[0].clone();
    }
    if scopes.iter().any(|scope| scope.where_clause == "1=1") {
        return SqlScope::allow_all();
    }
    let where_clause = scopes
        .iter()
        .map(|scope| format!("({})", scope.where_clause))
        .collect::<Vec<_>>()
        .join(" OR ");
    let params = scopes.iter().flat_map(|scope| scope.params.clone()).collect();
    SqlScope { where_clause, params }
}
