package main

workload_resources = [
  "ReplicaSet",
  "Deployment",
  "DaemonSet",
  "StatefulSet",
  "Job",
]

deny[msg] {
  resources := input[_][_]
  others := input[_][_]

  resources.kind == workload_resources[_]
  others.kind == workload_resources[_]

  resources.spec.template.metadata.labels == others.spec.template.metadata.labels
  resources.metadata.name != others.metadata.name

  msg = sprintf("リソースのラベルが衝突しています: [%s/%s <=> %s/%s]", [resources.kind, resources.metadata.name, others.kind, others.metadata.name])
}

svc_related_deployment(svc, others) = x {
  others.kind == workload_resources[_]
  x = (svc.spec.selector == others.spec.template.metadata.labels)
}

deny[msg] {
  resources := input[_][_]
  resources.kind == "Service"
  ret = svc_related_deployment(resources, input[_][_])
  not ret
  msg = sprintf("Service の Selector に対応する Workloads リソースが存在しません: [%s/%s, %s]", [resources.kind, resources.metadata.name, resources.spec.selector])
}

