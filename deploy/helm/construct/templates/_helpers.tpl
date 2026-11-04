{{/* Common labels; app.kubernetes.io/name is what K8sRunner's NetworkPolicies select on. */}}
{{- define "construct.labels" -}}
app.kubernetes.io/name: {{ .name }}
app.kubernetes.io/part-of: construct
app.kubernetes.io/instance: {{ .root.Release.Name }}
{{- end }}

{{/* A secret value: the given one, else the one already in the cluster, else a new random one. */}}
{{- define "construct.secret" -}}
{{- $given := index .root.Values.secrets .key -}}
{{- if $given -}}{{ $given }}
{{- else -}}
{{- $existing := lookup "v1" "Secret" .root.Release.Namespace "construct-secrets" -}}
{{- if and $existing (index $existing.data .key) -}}{{ index $existing.data .key | b64dec }}
{{- else -}}{{ randAlphaNum 40 }}{{- end -}}
{{- end -}}
{{- end }}

{{/* A provider key: the given one, else the one already in the cluster (an upgrade without it keeps it), else "". */}}
{{- define "construct.keepSecret" -}}
{{- $given := index .root.Values.secrets .key -}}
{{- if $given -}}{{ $given }}
{{- else -}}
{{- $existing := lookup "v1" "Secret" .root.Release.Namespace "construct-secrets" -}}
{{- if and $existing (index $existing.data .key) -}}{{ index $existing.data .key | b64dec }}{{- end -}}
{{- end -}}
{{- end }}

{{/* Pod/container hardening for the control-plane services (the prsec image runs as uid 10001). */}}
{{- define "construct.podSecurity" -}}
runAsNonRoot: true
runAsUser: 10001
runAsGroup: 10001
seccompProfile: {type: RuntimeDefault}
{{- end }}
{{- define "construct.containerSecurity" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities: {drop: [ALL]}
{{- end }}

{{/* PRSEC_* settings shared by api, worker, launcher and dashboard. */}}
{{- define "construct.prsecEnv" -}}
- name: PRSEC_LOG_FORMAT
  value: json
- name: PRSEC_DB_PASSWORD
  valueFrom: {secretKeyRef: {name: construct-secrets, key: dbPassword}}
- name: PRSEC_DATABASE_URL
  {{- if .Values.postgres.enabled }}
  value: "postgresql://prsec:$(PRSEC_DB_PASSWORD)@postgres:5432/prsec"
  {{- else }}
  value: {{ required "externalDatabaseUrl is required when postgres.enabled is false" .Values.externalDatabaseUrl | quote }}
  {{- end }}
- name: PRSEC_POLICY_PATH
  value: /etc/prsec/policy.yaml
- name: PRSEC_SKILLS_VERSION
  value: {{ .Values.skillsVersion | quote }}
- name: PRSEC_WORK_ROOT
  value: {{ printf "%s/work" .Values.storage.dataRoot }}
- name: PRSEC_SKILLS_DIR
  value: {{ printf "%s/skills/current" .Values.storage.dataRoot }}
- name: PRSEC_HARNESS_ROOT
  value: {{ printf "%s/harness" .Values.storage.dataRoot }}
- name: PRSEC_SARIF_DIR
  value: {{ printf "%s/work/artifacts" .Values.storage.dataRoot }}
{{- if .Values.github.appId }}
- name: PRSEC_GITHUB_APP_ID
  value: {{ .Values.github.appId | quote }}
- name: PRSEC_GITHUB_PRIVATE_KEY_PATH
  value: /run/secrets/github/app.pem
{{- end }}
{{- end }}

{{/* The volumes every prsec service mounts: policy, data volume, github key, tmp. */}}
{{- define "construct.prsecVolumes" -}}
- name: policy
  configMap: {name: construct-policy}
- name: data
  persistentVolumeClaim: {claimName: {{ .Values.storage.claimName }}}
- name: github
  secret: {secretName: construct-github, optional: true}
- name: tmp
  emptyDir: {sizeLimit: 256Mi}
{{- end }}
{{- define "construct.prsecMounts" -}}
- {name: policy, mountPath: /etc/prsec, readOnly: true}
- {name: data, mountPath: {{ .Values.storage.dataRoot }}}
- {name: github, mountPath: /run/secrets/github, readOnly: true}
- {name: tmp, mountPath: /tmp}
{{- end }}

{{/* initContainer that applies the schema (advisory-locked, safe from several pods at once). */}}
{{- define "construct.migrate" -}}
- name: migrate
  image: {{ .Values.images.prsec }}
  imagePullPolicy: {{ .Values.images.pullPolicy }}
  command: [python, -c, "from prsec.db.conn import get_pool, migrate\nwith get_pool().connection() as c: migrate(c)"]
  env:
    {{- include "construct.prsecEnv" . | nindent 4 }}
  securityContext:
    {{- include "construct.containerSecurity" . | nindent 4 }}
  resources: {requests: {memory: 64Mi, cpu: 50m, ephemeral-storage: 16Mi}, limits: {memory: 256Mi, ephemeral-storage: 128Mi}}
{{- end }}

{{/* 'a', 'b' (CEL string list items) */}}
{{- define "construct.quotedList" -}}
{{- $out := list -}}
{{- range . }}{{ $out = append $out (printf "'%s'" .) }}{{ end -}}
{{- join ", " $out -}}
{{- end }}
