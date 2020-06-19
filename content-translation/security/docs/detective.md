# 审核和记录
出于各种不同的原因，收集和分析\[审计\]日志很有用。 日志可帮助进行根本原因分析和归因，即将更改归因于特定用户。 收集到足够的日志后，它们也可以用于检测异常行为。 在EKS上，审核日志将发送到Amazon Cloudwatch日志。 EKS的审核策略当前在辅助脚本中增加了参考[policy](https://github.com/kubernetes/kubernetes/blob/master/cluster/gce/gci/configure-helper.sh#L983-L1108) 以下政策: 

```yaml
- level: RequestResponse
    namespaces: ["kube-system"]
    verbs: ["update", "patch", "delete"]
    resources:
      - group: "" # core
        resources: ["configmaps"]
        resourceNames: ["aws-auth"]
    omitStages:
      - "RequestReceived"
```
这会将更改记录到 `aws-auth` ConfigMap中，该映射用于授予对EKS集群的访问权限. 

## 推荐建议

### Enable audit logs
审核日志是EKS管理的EKS管理的Kubernetes控制平面日志的一部分。 可以在此处找到启用/禁用控制平面日志的说明，其中包括Kubernetes API服务器，控制器管理器和调度程序的日志以及审核日志, https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html#enabling-control-plane-log-export. 

!!! 信息
    启用控制平面日志记录时，将产生[费用](https://aws.amazon.com/cloudwatch/pricing/)，用于将日志存储在CloudWatch中。 这引起了有关安全成本的广泛问题。 最终，您将不得不权衡这些成本与安全漏洞的成本，例如 经济损失，名誉受损等。您可能会发现，仅实施本指南中的某些建议即可充分保护环境. 

!!! 警告
    CWL条目的最大大小为256KB，而Kubernetes API请求的最大大小为1.5MiB.

### 利用审计元数据
Kubernetes审核日志包含两个注释，它们指示请求是否已被授权`authorization.k8s.io/decision`以及做出决定`authorization.k8s.io/reason`的原因。 使用这些属性来确定为什么允许特定的API调用. 
   
### 为可疑事件创建警报
创建一个警报以自动提醒您403禁止响应和401未经授权响应的增加，然后使用`host`, `sourceIPs`和`k8s_user.username`之类的属性来查找这些请求的来源。
  
### 使用Log Insights分析日志
使用CloudWatch Log Insights监视对RBAC对象的更改，例如 角色，RoleBindings，ClusterRoles和ClusterRoleBindings。 以下是一些示例查询: 

列出对角色的创建，更新，删除操作:
```
fields @timestamp, @message
| sort @timestamp desc
| limit 100
| filter objectRef.resource="roles" and verb in ["create", "update", "patch", "delete"]
```
列出对RoleBindings的创建，更新，删除操作:
```
fields @timestamp, @message
| sort @timestamp desc
| limit 100
| filter objectRef.resource="rolebindings" and verb in ["create", "update", "patch", "delete"]
```
列出对ClusterRoles的创建，更新，删除操作:
```
fields @timestamp, @message
| sort @timestamp desc
| limit 100
| filter objectRef.resource="clusterroles" and verb in ["create", "update", "patch", "delete"]
```
列出对ClusterRoleBindings的创建，更新，删除操作:
```
fields @timestamp, @message
| sort @timestamp desc
| limit 100
| filter objectRef.resource="clusterrolebindings" and verb in ["create", "update", "patch", "delete"]
```
针对Secrets策划未经授权的读取操作:
```
fields @timestamp, @message
| sort @timestamp desc
| limit 100
| filter objectRef.resource="secrets" and verb in ["get", "watch", "list"] and responseStatus.code="401"
| count() by bin(1m)
```
失败的匿名请求列表:
```
fields @timestamp, @message, sourceIPs.0
| sort @timestamp desc
| limit 100
| filter user.username="system:anonymous" and responseStatus.code in ["401", "403"]
```

### 审核您的CloudTrail日志
使用服务帐户的IAM角色的Pod调用的AWS API会与服务帐户的名称一起自动登录到CloudTrail。 如果未明确授权调用API的服务帐户的名称出现在日志中，则可能表明IAM角色的信任策略配置错误。 一般而言，Cloudtrail是将AWS API调用分配给特定IAM主体的好方法. 

### 额外资源
随着日志数量的增加，使用Log Insights或其他日志分析工具进行解析和过滤可能会失效。 作为替代方案，您可能要考虑运行[Sysdig Falco](https://github.com/falcosecurity/falco) 和 [ekscloudwatch](https://github.com/sysdiglabs/ekscloudwatch).。 Falco分析审核日志，并在很长一段时间内标记异常或滥用情况。 ekscloudwatch项目将审核日志事件从CloudWatch转发到Falco进行分析。 Falco提供了一组[默认审核规则](https://github.com/falcosecurity/falco/blob/master/rules/k8s_audit_rules.yaml)以及添加自己的功能. 

另一个选择可能是将审核日志存储在S3中，并使用SageMaker  [Random Cut Forest](https://docs.aws.amazon.com/sagemaker/latest/dg/randomcutforest.html) 算法来确保异常行为 进一步的调查.

## Tooling
以下开源项目可用于评估集群与既定最佳实践的一致性:

+ [kubeaudit](https://github.com/Shopify/kubeaudit)
+ [MKIT](https://github.com/darkbitio/mkit)
+ [kubesec.io](https://kubesec.io/)
+ [polaris](https://github.com/FairwindsOps/polaris)
+ [kAudit](https://www.alcide.io/kaudit-K8s-forensics/)
