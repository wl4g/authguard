{{- define "customer-growth-e2e.name" -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "customer-growth-e2e.keycloakName" -}}
{{- printf "%s-e2e-keycloak" (include "customer-growth-e2e.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "customer-growth-e2e.keycloakSecretName" -}}
{{- printf "%s-e2e-keycloak-credentials" (include "customer-growth-e2e.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "customer-growth-e2e.principalDiscoverySecretName" -}}
{{- printf "%s-e2e-principal-discovery-credentials" (include "customer-growth-e2e.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "customer-growth-e2e.ldapName" -}}
{{- printf "%s-e2e-ldap" (include "customer-growth-e2e.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "customer-growth-e2e.jaegerName" -}}
{{- printf "%s-e2e-jaeger" (include "customer-growth-e2e.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "customer-growth-e2e.postgresqlName" -}}
{{- printf "%s-e2e-postgresql" (include "customer-growth-e2e.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "customer-growth-e2e.workloadName" -}}
{{- printf "%s-e2e-%s" (include "customer-growth-e2e.name" .root) .component | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "customer-growth-e2e.mockIdpName" -}}
{{- printf "%s-e2e-mock-idp" (include "customer-growth-e2e.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "customer-growth-e2e.accessContextSecretName" -}}
{{- default (printf "%s-e2e-authguard-access-context" (include "customer-growth-e2e.name" .)) .Values.authguard.accessContext.secretName | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "customer-growth-e2e.labels" -}}
app.kubernetes.io/part-of: e2e-customer-growth-authguard
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
