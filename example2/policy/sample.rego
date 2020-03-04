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

