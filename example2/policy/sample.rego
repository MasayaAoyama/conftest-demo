package main

workload_resources = [
  "ReplicaSet",
  "Deployment",
  "DaemonSet",
  "StatefulSet",
  "Job",
]

deny[msg] {
  files := input[_]
  resources := files[_]
  other_files := input[_]
  other_resources := other_files[_]

  resources.kind == workload_resources[_]
  other_resources.kind == workload_resources[_]

  resources.spec.template.metadata.labels == other_resources.spec.template.metadata.labels
  resources.metadata.name != other_resources.metadata.name

  msg = sprintf("リソースのラベルが衝突しています: [%s/%s <=> %s/%s]", [resources.kind, resources.metadata.name, other_resources.kind, other_resources.metadata.name])
}

svc_related_deployment(svc, other_resource) = x {
  other_resource.kind == workload_resources[_]
  x = (svc.spec.selector == other_resource.spec.template.metadata.labels)
}

deny[msg] {
  files := input[_]
  resources := files[_]
  other_files := input[_]
  other_resources := other_files[_]

  resources.kind == "Service"
  ret = svc_related_deployment(resources, other_resources)
  not ret
  msg = sprintf("Service の Selector に対応する Workloads リソースが存在しません: [%s/%s, %s]", [resources.kind, resources.metadata.name, resources.spec.selector])
}

