{{- define "customer-growth-e2e.name" -}}
customer-growth
{{- end -}}

{{- define "customer-growth-e2e.keycloakName" -}}
keycloak
{{- end -}}

{{- define "customer-growth-e2e.keycloakSecretName" -}}
keycloak-credentials
{{- end -}}

{{- define "customer-growth-e2e.principalDiscoverySecretName" -}}
principal-discovery-credentials
{{- end -}}

{{- define "customer-growth-e2e.ldapName" -}}
ldap
{{- end -}}

{{- define "customer-growth-e2e.jaegerName" -}}
jaeger
{{- end -}}

{{- define "customer-growth-e2e.postgresqlName" -}}
postgresql
{{- end -}}

{{- define "customer-growth-e2e.workloadName" -}}
{{- .component -}}
{{- end -}}

{{- define "customer-growth-e2e.mockIdpName" -}}
mock-idp
{{- end -}}

{{- define "customer-growth-e2e.anvilName" -}}
anvil
{{- end -}}

{{- define "customer-growth-e2e.solanaName" -}}
solana
{{- end -}}

{{- define "customer-growth-e2e.accessContextSecretName" -}}
{{- $authguard := index .Values "authguard-middleware" -}}
{{- default "access-context" $authguard.accessContext.secretName | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "customer-growth-e2e.labels" -}}
app.kubernetes.io/part-of: customer-growth
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
