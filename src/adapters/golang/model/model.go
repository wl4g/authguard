package model

import (
	"encoding/json"
	"fmt"
	"time"
)

const AccessContextVersion = 3

type SqlScope struct {
	Where string
	Args  []any
}

type AccessGrantSet struct {
	AllowResourceURNs []string
	DenyResourceURNs  []string
}

type AccessContext struct {
	Version           int      `json:"version"`
	PrincipalID       string   `json:"principal_id"`
	Action            string   `json:"action"`
	ResourceURN       string   `json:"resource_urn"`
	AllowResourceURNs []string `json:"allow_resource_urns"`
	DenyResourceURNs  []string `json:"deny_resource_urns"`
	PolicyRevision    uint64   `json:"policy_revision"`
	IssuedAtEpochSec  uint64   `json:"issued_at_epoch_seconds"`
	ExpiresAtEpochSec uint64   `json:"expires_at_epoch_seconds"`
}

func NewAccessContext(
	principalID string,
	action string,
	resourceURN string,
	allowResourceURNs []string,
	denyResourceURNs []string,
	policyRevision uint64,
	ttl time.Duration,
) AccessContext {
	now := uint64(time.Now().Unix())
	return AccessContext{
		Version: AccessContextVersion, PrincipalID: principalID, Action: action, ResourceURN: resourceURN,
		AllowResourceURNs: allowResourceURNs, DenyResourceURNs: denyResourceURNs,
		PolicyRevision: policyRevision, IssuedAtEpochSec: now,
		ExpiresAtEpochSec: now + uint64(ttl/time.Second),
	}
}

type RequestAccess struct {
	PrincipalID string
	Action      string
	ResourceURN string
	Grants      AccessGrantSet
}

func (c AccessContext) GrantSet() AccessGrantSet {
	return AccessGrantSet{
		AllowResourceURNs: append([]string(nil), c.AllowResourceURNs...),
		DenyResourceURNs:  append([]string(nil), c.DenyResourceURNs...),
	}
}

func (c AccessContext) RequestAccess() RequestAccess {
	return RequestAccess{
		PrincipalID: c.PrincipalID, Action: c.Action, ResourceURN: c.ResourceURN, Grants: c.GrantSet(),
	}
}

// UnmarshalJSON accepts the v3 canonical field names and the v3 transition
// aliases used by older SDKs. Marshal uses only the canonical struct tags.
func (c *AccessContext) UnmarshalJSON(data []byte) error {
	type canonical AccessContext
	var wire struct {
		canonical
		PrincipalID         *string `json:"principal_id"`
		LegacySubjectID     *string `json:"subject_id"`
		PolicyRevision      *uint64 `json:"policy_revision"`
		LegacyPolicyVersion *uint64 `json:"policy_version"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	principalID, err := compatibleStringAlias(
		"principal_id", wire.PrincipalID, "subject_id", wire.LegacySubjectID,
	)
	if err != nil {
		return err
	}
	policyRevision, err := compatibleUint64Alias(
		"policy_revision", wire.PolicyRevision, "policy_version", wire.LegacyPolicyVersion,
	)
	if err != nil {
		return err
	}
	*c = AccessContext(wire.canonical)
	c.PrincipalID = principalID
	c.PolicyRevision = policyRevision
	return nil
}

func compatibleStringAlias(
	canonicalName string,
	canonicalValue *string,
	legacyName string,
	legacyValue *string,
) (string, error) {
	if canonicalValue != nil && legacyValue != nil && *canonicalValue != *legacyValue {
		return "", fmt.Errorf("conflicting access context fields %s and %s", canonicalName, legacyName)
	}
	if canonicalValue != nil {
		return *canonicalValue, nil
	}
	if legacyValue != nil {
		return *legacyValue, nil
	}
	return "", nil
}

func compatibleUint64Alias(
	canonicalName string,
	canonicalValue *uint64,
	legacyName string,
	legacyValue *uint64,
) (uint64, error) {
	if canonicalValue != nil && legacyValue != nil && *canonicalValue != *legacyValue {
		return 0, fmt.Errorf("conflicting access context fields %s and %s", canonicalName, legacyName)
	}
	if canonicalValue != nil {
		return *canonicalValue, nil
	}
	if legacyValue != nil {
		return *legacyValue, nil
	}
	return 0, nil
}

type SegmentMap struct {
	Kind  SegmentKind
	Value string
}

type PathMap struct {
	Kind  PathKind
	Value string
}

type ResourceSQLMapping struct {
	Partition SegmentMap
	Service   SegmentMap
	Region    SegmentMap
	Tenant    SegmentMap
	Path      []PathMap
}

type URNPattern struct {
	Partition string
	Service   string
	Region    string
	Tenant    string
	Path      []string
}

type SegmentKind int

const (
	SegmentConstant SegmentKind = iota
	SegmentColumn
)

type PathKind int

const (
	PathLiteral PathKind = iota
	PathColumn
	PathRemainderColumn
)

func EmptyAccessGrantSet() AccessGrantSet {
	return AccessGrantSet{AllowResourceURNs: []string{}, DenyResourceURNs: []string{}}
}

func ConstSegment(value string) SegmentMap {
	return SegmentMap{Kind: SegmentConstant, Value: value}
}

func ColumnSegment(name string) SegmentMap {
	return SegmentMap{Kind: SegmentColumn, Value: name}
}

func LiteralPath(value string) PathMap {
	return PathMap{Kind: PathLiteral, Value: value}
}

func ColumnPath(name string) PathMap {
	return PathMap{Kind: PathColumn, Value: name}
}

func RemainderColumnPath(name string) PathMap {
	return PathMap{Kind: PathRemainderColumn, Value: name}
}
