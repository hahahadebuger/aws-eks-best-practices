# 事件响应和取证
您对事件做出快速反应的能力可以帮助最大程度地减少违规造成的损失。 拥有一个可警告您可疑行为的可靠警报系统，是好的事件响应计划的第一步。 当确实发生事故时，您必须快速决定是要销毁和更换容器，还是隔离并检查容器。 如果选择隔离容器以进行法医调查和根本原因分析，则应遵循以下活动:

## 样本事件响应计划

### 确定有问题的Pod和工作节点
您的第一个操作步骤应该是隔离损坏。 首先确定发生漏洞的位置，并将该Pod及其节点与其他基础架构隔离.
### 通过创建拒绝所有到该Pod的入口和出口流量的网络策略来隔离Pod
拒绝所有流量规则可以通过切断与吊舱的所有连接来帮助阻止已经在进行的攻击。 以下网络政策将应用于标签为`app=web`的pod. 
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
spec:
  podSelector:
    matchLabels: 
      app: web
  policyTypes:
  - Ingress
  - Egress
```

!!! 注意 
    如果攻击者获得了对基础主机的访问权限，则网络策略可能无效。 如果您怀疑发生了这种情况，可以使用[AWS安全组](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html)将受感染的主机与其他主机隔离。 更改主机的安全组时，请注意它将影响该主机上运行的所有容器.  

### 如有必要，撤消分配给pod或worker节点的临时安全凭证
如果为工作节点分配了IAM角色，该角色允许Pod获得对其他AWS资源的访问权限，请从实例中删除这些角色，以防止受到攻击的进一步损害。 同样，如果为Pod分配了IAM角色，请评估是否可以安全地从角色中删除IAM策略而不影响其他工作负载.

### 封锁(Cordon)工作节点
通过封锁受影响的工作节点，可以通知调度程序，避免将Pod调度到受影响的节点上。 这将使您可以删除要进行法医研究的节点，而不会破坏其他工作负载.

!!! info
    本指南不适用于Fargate，因为每个Fargate Pod都在其自己的沙盒环境中运行。 通过应用拒绝所有入站和出站流量的网络策略来隔离受感染的Fargate Pod，而不是进行封锁. 

### 在受影响的工作节点上启用终止保护
攻击者可能试图通过终止受影响的节点来消除其不良行为。 启用[终止保护](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/terminating-instances.html#Using_ChangingDisableAPITermination)）可以防止这种情况的发生。 [实例缩容保护](https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-instance-termination.html#instance-protection)将保护节点免受缩容事件的影响. 

!!! 警告 
    您无法在竞价型实例上启用终止保护. 

### 在标签上标记有问题的Pod/节点，该标签表明是主动调查的一部分
这将向群集管理员发出警告，请在调查完成之前不要篡改受影响的Pod/Node。. 

### 在工作节点上捕获易失工件
+ **捕获操作系统内存**. 这将捕获每个容器的Docker守护进程及其子进程。 [MargaritaShotgun](https://github.com/ThreatResponse/margaritashotgun)，一种远程内存获取工具，可以帮助实现这一目标. 
+ **对正在运行的进程和打开的端口执行netstat树转储**. 这将捕获每个容器的docker守护进程及其子进程. 
+ **在工作节点上更改证据之前运行docker命令**.
    + `docker container top CONTAINER` for processes running.
    + `docker container logs CONTAINER` 查看守护程序级别的保留日志.
    + `docker container port CONTAINER` for list of open ports.
    + `docker container diff CONTAINER` 捕获自容器首次启动以来文件和目录对容器文件系统的更改.   
+ **暂停容器以进行取证**.
+ **快照实例的EBS卷**.

## 推荐建议

### 查看AWS安全事件响应白皮书
尽管本节提供了简要概述以及一些处理可疑安全漏洞的建议，但该白皮书在[AWS安全事件响应](https://d1.awsstatic.com/whitepapers/aws_security_incident_response.pdf)白皮书中进行了详尽介绍。(https://d1.awsstatic.com/whitepapers/aws_security_incident_response.pdf).

### 练习安全游戏日
将您的安全从业人员分为2组：红色和蓝色。 红色团队将专注于探索不同系统的漏洞，而蓝色团队将负责防御漏洞。 如果您没有足够的安全从业人员来创建独立的团队，请考虑雇用一个具有Kubernetes漏洞知识的外部实体. 

### 针对您的集群运行渗透测试
定期攻击您自己的群集可以帮助您发现漏洞和配置错误。 在开始之前，请按照[渗透测试准则](https://aws.amazon.com/security/penetration-testing/)进行针对群集的测试. 

## 工具
+ [kube-hunter](https://github.com/aquasecurity/kube-hunter), Kubernetes的渗透测试工具. 
+ [Gremlin](https://www.gremlin.com/product/#kubernetes), 一个混乱工程工具包，可用于模拟针对您的应用程序和基础架构的攻击。 
+ [kube-forensics](https://github.com/keikoproj/kube-forensics), Kubernetes控制器触发一个作业，该作业收集正在运行的Pod的状态并将其转储到S3存储桶中. 
+ [攻击和防御Kubernetes安装](https://github.com/kubernetes/community/blob/master/wg-security-audit/findings/AtredisPartners_Attacking_Kubernetes-v1.0.pdf)
