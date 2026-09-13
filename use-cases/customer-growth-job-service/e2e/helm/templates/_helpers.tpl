{{- define "customer-growth-e2e.name" -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "customer-growth-e2e.keycloakName" -}}
{{- printf "%s-keycloak" (include "customer-growth-e2e.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "customer-growth-e2e.keycloakSecretName" -}}
{{- printf "%s-keycloak-credentials" (include "customer-growth-e2e.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "customer-growth-e2e.principalDiscoverySecretName" -}}
{{- printf "%s-principal-discovery-credentials" (include "customer-growth-e2e.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "customer-growth-e2e.ldapName" -}}
{{- printf "%s-ldap" (include "customer-growth-e2e.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "customer-growth-e2e.jaegerName" -}}
{{- printf "%s-jaeger" (include "customer-growth-e2e.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "customer-growth-e2e.postgresqlName" -}}
{{- printf "%s-postgresql" (include "customer-growth-e2e.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "customer-growth-e2e.workloadName" -}}
{{- printf "%s-%s" (include "customer-growth-e2e.name" .root) .component | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "customer-growth-e2e.mockIdpName" -}}
{{- printf "%s-mock-idp" (include "customer-growth-e2e.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "customer-growth-e2e.accessContextSecretName" -}}
{{- default (printf "%s-access-context" (include "customer-growth-e2e.name" .)) .Values.authguard.accessContext.secretName | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "customer-growth-e2e.labels" -}}
app.kubernetes.io/part-of: e2e-authguard-customer-growth
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
