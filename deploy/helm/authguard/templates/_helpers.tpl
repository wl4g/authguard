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
app.kubernetes.io/component: server
{{- end -}}

{{- define "authguard.serviceAccountName" -}}
{{- if .Values.authguard.serviceAccount.create -}}
{{- default (include "authguard.fullname" .) .Values.authguard.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.authguard.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "authguard.oidcSecretName" -}}
{{- default (printf "%s-oidc" (include "authguard.fullname" .)) .Values.authguardIntegration.oidc.existingSecret -}}
{{- end -}}

{{- define "authguard.accessContextSecretName" -}}
{{- default (printf "%s-access-context" (include "authguard.fullname" .)) .Values.authguard.accessContext.existingSecret -}}
{{- end -}}

{{- define "authguard.jwtJwksConfigMapName" -}}
{{- default (printf "%s-jwt-jwks" (include "authguard.fullname" .)) .Values.authguardIntegration.jwt.localJWKS.existingConfigMap -}}
{{- end -}}

{{- define "authguard.redisFullname" -}}
{{- $redis := index .Values "redis-cluster" -}}
{{- default (printf "%s-redis-cluster" .Release.Name | trunc 63 | trimSuffix "-") $redis.fullnameOverride -}}
{{- end -}}

{{- define "authguard.redisSecretName" -}}
{{- $redis := index .Values "redis-cluster" -}}
{{- default (include "authguard.redisFullname" .) $redis.existingSecret -}}
{{- end -}}

{{- define "authguard.redisPasswordKey" -}}
{{- $redis := index .Values "redis-cluster" -}}
{{- default "redis-password" $redis.existingSecretPasswordKey -}}
{{- end -}}

{{- define "authguard.joinPath" -}}
{{- if eq .context "/" -}}
{{- .path -}}
{{- else -}}
{{- printf "%s%s" (trimSuffix "/" .context) .path -}}
{{- end -}}
{{- end -}}
