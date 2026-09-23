{{- define "authguard.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "authguard.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "authguard.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "authguard.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "authguard.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "authguard.selectorLabels" -}}
app.kubernetes.io/name: {{ include "authguard.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "authguard.serverSelectorLabels" -}}
{{ include "authguard.selectorLabels" . }}
app.kubernetes.io/component: authz
{{- end -}}

{{- define "authguard.authnSelectorLabels" -}}
{{ include "authguard.selectorLabels" . }}
app.kubernetes.io/component: authn
{{- end -}}

{{- define "authguard.webSelectorLabels" -}}
{{ include "authguard.selectorLabels" . }}
app.kubernetes.io/component: web
{{- end -}}

{{- define "authguard.serviceAccountName" -}}
{{- if .Values.authguard.authz.serviceAccount.create -}}
{{- default (include "authguard.fullname" .) .Values.authguard.authz.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.authguard.authz.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "authguard.secretsProvider" -}}
{{- lower (default "kubernetes" .Values.secrets.provider) -}}
{{- end -}}

{{- define "authguard.canonicalJwksConfigMapName" -}}
{{- default (printf "%s-canonical-jwks" (include "authguard.fullname" .)) .Values.authguard.authn.canonical_jwt.local_jwks.existing_config_map -}}
{{- end -}}

{{/* Render the runtime configuration once so ConfigMap content and rollout
     checksum always describe exactly the same effective configuration. */}}
{{- define "authguard.runtimeConfig" -}}
{{- $runtimeConfig := index .Values.authguard "authguard-config" | default "" -}}
{{- if not $runtimeConfig -}}
{{- fail "authguard.authguard-config must contain the full authguard.yaml content" -}}
{{- end -}}
{{- $renderedConfig := tpl $runtimeConfig . -}}
{{- $applications := .Values.authguard.authn.applications | default dict -}}
{{- if $applications -}}
{{- $parsedConfig := fromYaml $renderedConfig -}}
{{- if not (kindIs "map" $parsedConfig) -}}
{{- fail "authguard.authguard-config must render valid YAML" -}}
{{- end -}}
{{- $authnConfig := index $parsedConfig "authn" | default dict -}}
{{- $_ := set $authnConfig "applications" $applications -}}
{{- $_ := set $parsedConfig "authn" $authnConfig -}}
{{- $renderedConfig = toYaml $parsedConfig -}}
{{- end -}}
{{- $renderedConfig -}}
{{- end -}}

{{- define "authguard.runtimeConfigChecksum" -}}
{{- include "authguard.runtimeConfig" . | sha256sum -}}
{{- end -}}

{{- define "authguard.redisFullname" -}}
{{- $redis := .Values.redis_cluster -}}
{{- default (printf "%s-redis-cluster" .Release.Name | trunc 63 | trimSuffix "-") $redis.fullnameOverride -}}
{{- end -}}

{{- define "authguard.redisSecretName" -}}
{{- $redis := .Values.redis_cluster -}}
{{- default (include "authguard.redisFullname" .) $redis.existingSecret -}}
{{- end -}}

{{- define "authguard.redisPasswordKey" -}}
{{- $redis := .Values.redis_cluster -}}
{{- default "redis-password" $redis.existingSecretPasswordKey -}}
{{- end -}}

{{- define "authguard.postgresqlFullname" -}}
{{- $postgres := .Values.postgresql -}}
{{- default (printf "%s-postgresql" .Release.Name | trunc 63 | trimSuffix "-") $postgres.fullnameOverride -}}
{{- end -}}

{{- define "authguard.joinPath" -}}
{{- if eq .context "/" -}}
{{- .path -}}
{{- else -}}
{{- printf "%s%s" (trimSuffix "/" .context) .path -}}
{{- end -}}
{{- end -}}

{{/* Env-file path for the cloud providers; vault owns its path. */}}
{{- define "authguard.csiSecretsMountPath" -}}
/etc/authguard/csi
{{- end -}}

{{/* Vault Agent Injector annotations. The KV secret's data.env value must be
    the multi-line "ENV KEY=VALUE" content consumed through
    AUTHGUARD__SECRETS__ENV_FILE. */}}
{{- define "authguard.vaultAnnotations" -}}
vault.hashicorp.com/agent-inject: "true"
vault.hashicorp.com/role: {{ required "secrets.vault.vaultRole is required when secrets.provider=vault" .Values.secrets.vault.vaultRole | quote }}
vault.hashicorp.com/agent-init-first: "true"
vault.hashicorp.com/agent-inject-secret-env: {{ required "secrets.vault.secretPath is required when secrets.provider=vault" .Values.secrets.vault.secretPath | quote }}
vault.hashicorp.com/agent-inject-template-env: |
  {{ print "{{" }}- with secret {{ .Values.secrets.vault.secretPath | quote }} -{{ print "}}" }}
  {{ print "{{" }} .Data.data.env {{ print "}}" }}
  {{ print "{{" }}- end -{{ print "}}" }}
{{- end -}}
