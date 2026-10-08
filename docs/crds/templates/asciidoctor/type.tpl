{{- define "type" -}}
{{- $type := . -}}
{{- if asciidocShouldRenderType $type -}}

[id="{{ asciidocTypeID $type | asciidocRenderAnchorID }}"]
==== {{ $type.Name  }}

{{ if $type.IsAlias }}_Underlying type:_ _{{ asciidocRenderTypeLink $type.UnderlyingType  }}_{{ end }}

{{ $type.Doc }}

{{ if $type.Validation -}}
.Validation:
{{- range $type.Validation }}
- {{ . }}
{{- end }}
{{- end }}

{{ if $type.References -}}
.Appears In:
****
{{- range $type.SortedReferences }}
- {{ asciidocRenderTypeLink . }}
{{- end }}
****
{{- end }}

{{ if $type.Members -}}
[cols="20a,50a,15a,15a", options="header"]
|===
| Field | Description | Default | Validation
{{ if $type.GVK -}}
| *`apiVersion`* __string__ | `{{ $type.GVK.Group }}/{{ $type.GVK.Version }}` | |
| *`kind`* __string__ | `{{ $type.GVK.Kind }}` | |
{{ end -}}

{{ range $type.Members -}}
{{- /* crd-ref-docs emits valueless markers as "Optional: {}", which the renderer
       then escapes into "Optional: \{}". Trim the empty value until the upstream
       fix lands: https://github.com/elastic/crd-ref-docs/issues/198 */ -}}
| *`{{ .Name  }}`* __{{ asciidocRenderType .Type }}__ | {{ template "type_members" . }} | {{ .Default }} | {{ range .Validation -}} {{ asciidocRenderValidation (trimSuffix ": {}" .) }} +
{{ end }}
{{ end -}}
|===
{{ end -}}

{{- end -}}
{{- end -}}
