# 合规
合规性是AWS及其服务使用者之间的共同责任。 一般而言，AWS负责“云的安全性”，而其用户负责“云内的安全性”。 描绘AWS及其用户负责的内容的行会因服务而异。 例如，对于Fargate，AWS负责管理其数据中心，硬件，虚拟基础架构（Amazon EC2）和容器运行时（Docker）的物理安全性。 Fargate的用户负责保护容器映像及其应用程序。 在运行必须遵守合规性标准的工作负载时，了解谁负责什么是重要的考虑因素.

下表显示了不同容器服务所遵循的合规性程序.

| 合规计划 | Amazon ECS 编排 | Amazon EKS 编排| ECS Fargate | Amazon ECR |
| ------------------ |:----------:|:----------:|:-----------:|:----------:|
| PCI DSS Level 1	| 1 | 1 | 1 | 1 |
| HIPAA Eligible	| 1 | 1	| 1	| 1 |
| SOC I | 1 | 1 | 1 | 1 |
| SOC II | 1 |	1 |	1 |	1 |
| SOC III |	1 |	1 |	1 |	1 |
| ISO 27001:2013 | 1 | 1 | 1 | 1 |
| ISO 9001:2015 | 1 | 1 | 1 | 1 |
| ISO 27017:2015 |	1 |	1 |	1 |	1 |
| ISO 27018:2019 |	1 |	1 |	1 |	1 |
| IRAP | 1 | 0 | 1 | 1 |
| FedRAMP Moderate (East/West) | 1 | 3PAO Assessment | 0 | 1 |
| FedRAMP High (GovCloud) | 1 | 0 | 0 | 1 |
| DOD CC SRG | 1 |	Undergoing assessment |	0 |	1 |
| HIPAA BAA | 1 | 1 | 1 | 1 |
| MTCS | 1 | 1 | 0 | 1 |
| C5 | 1 | 1 | 0 | 1 |
| K-ISMS | 1 | 1 | 0 | 1 |
| ENS High | 1 | 1 | 0 | 1 |
| OSPAR | 1 | 0 | 0 | 1 | 
| HITRUSST CSF | 1 | 1 | 1 | 1 |

合规状态会随时间变化。 有关最新状态，请始终参考 https://aws.amazon.com/compliance/services-in-scope/. 

## Shifting left
shifting left的概念涉及在软件开发生命周期的早期捕获策略违规和错误。 从安全角度来看，这可能是非常有益的。 例如，开发人员可以在将应用程序部署到群集之前解决其配置问题。 像这样早些捕获错误将有助于防止违反策略的配置被部署。

### 策略
可以将策略视为控制行为的一组规则，即允许或禁止的行为。 例如，您可能有一个策略规定所有Dockerfile都应包含一个USER指令，该指令会导致该容器以非root用户身份运行。 作为文档，这样的策略可能很难发现和执行。 随着需求的变化，它可能也会过时.

## 推荐建议

### 使用开放策略代理（OPA）或Alcide的 sKan在部署之前检测策略违规

[OPA](https://www.openpolicyagent.org/) 是CNCF的一部分的开源策略引擎。 它用于制定政策决策，并且可以多种不同方式运行，例如 作为语言库或服务。 OPA策略以称为Rego的域特定语言（DSL）编写。 尽管OPA通常作为Kubernetes Dynamic Admission Controller的一部分运行，但它也可以集成到您的CI / CD管道中。 这使开发人员可以在发布周期的早期获得有关其配置的反馈，从而可以帮助他们在投入生产之前解决问题。.  

+ [Conftest](https://github.com/open-policy-agent/conftest) 在OPA之上构建，它为测试Kubernetes配置提供了以开发人员为中心的体验. 
+ [sKan](https://github.com/alcideio/skan) 由OPA提供支持，并“量身定制”以检查其Kubernetes配置文件是否符合安全性和操作最佳实践. 

## 工具和资源
+ [kube-bench](https://github.com/aquasecurity/kube-bench)
+ [docker-bench-security](https://github.com/docker/docker-bench-security)
+ [actuary](https://github.com/diogomonica/actuary)
+ [AWS Inspector](https://aws.amazon.com/inspector/)
+ [Kubernetes Security Review](https://github.com/kubernetes/community/blob/master/wg-security-audit/findings/Kubernetes%20Final%20Report.pdf) Kubernetes 1.13.4的第三方安全评估（2019）
