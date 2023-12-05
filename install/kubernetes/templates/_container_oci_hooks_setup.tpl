{{- define "container.tetragon-oci-hook-setup" -}}
- name: oci-hook-setup
  securityContext:
    privileged: true
  image: "{{ if .Values.tetragon.image.override }}{{ .Values.tetragon.image.override }}{{ else }}{{ .Values.tetragon.image.repository }}:{{ .Values.tetragon.image.tag | default .Chart.AppVersion }}{{ end }}"
  terminationMessagePolicy: FallbackToLogsOnError
  command: 
    - tetragon-oci-hook-setup
    - install
    - --interface={{ .Values.tetragon.ociHookSetup.interface }}
    - --local-install-dir={{  include "container.tetragonOCIHookSetup.installPath" . }}
    - --host-install-dir={{ .Values.tetragon.ociHookSetup.installDir }}
    - --oci-hooks.local-dir={{ include "container.tetragonOCIHookSetup.hooksPath" . }}
  volumeMounts:
    - name: oci-hooks-path
      mountPath: {{  include "container.tetragonOCIHookSetup.hooksPath" . }}
    - name: oci-hooks-install-path
      mountPath: {{  include "container.tetragonOCIHookSetup.installPath" . }}
{{- end -}}
