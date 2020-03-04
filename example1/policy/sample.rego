package main

workload_resources = [
  "ReplicaSet",
  "Deployment",
  "DaemonSet",
  "StatefulSet",
  "Job",
]

deny[msg] {
  input.kind == workload_resources[_]
  not (input.spec.selector.matchLabels.app == input.spec.template.metadata.labels.app)
  msg = sprintf("Pod Template 及び Selector には app ラベルを付与してください（spec.template.metadata.labels.app、spec.selector.matchLabels.app）: [Resource=%s, Name=%s, Selector=%v, Labels=%v]", [input.kind, input.metadata.name, input.spec.selector.matchLabels, input.spec.template.metadata.labels])
}
