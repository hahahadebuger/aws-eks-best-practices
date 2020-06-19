# 镜像安全
您应该将容器镜像视为抵御攻击的第一道防线。 不安全，结构不良的镜像可能使攻击者逃脱容器的限制并获得对主机的访问权限。 一旦到达主机，攻击者就可以访问敏感信息或在集群内或使用您的AWS账户横向移动。 以下最佳做法将有助于减轻这种情况的风险. 

## 推荐建议

### 创建最小的镜像
首先从容器镜像中删除所有无关的二进制文件。 如果您使用的是Dockerhub上不熟悉的镜像，请使用[Dive](https://github.com/wagoodman/dive)之类的应用程序检查该镜像，该应用程序可以向您显示容器各层的内容。 删除所有具有SETUID和SETGID位的二进制文件，因为它们可用于提升特权，并考虑删除所有可用于恶意目的的shell和实用程序（例如nc和curl）。 您可以使用以下命令找到具有SETUID和SETGID位的文件:
```bash
find / -perm +6000 -type f -exec ls -ld {} \;
```
    
要从这些文件中删除特殊权限，请将以下指令添加到您的容器镜像中:
```dockerfile
RUN find / -xdev -perm +6000 -type f -exec chmod a-s {} \; || true
```
通俗地讲，这就是所谓的“使镜像变形(de-fanging)”. 
  
### 使用多阶段构建
使用多阶段构建是一种创建最小镜像的方法。 通常，多阶段构建用于自动化持续集成周期的各个部分。 例如，可以使用多阶段构建来整理源代码或执行静态代码分析。 这为开发人员提供了获得即时反馈的机会，而不是等待管道执行。 从安全的角度来看，多阶段构建很有吸引力，因为它们使您可以最小化推送到容器注册表的最终镜像的大小。 没有构建工具和其他无关二进制文件的容器镜像可通过减少镜像的受攻击面来改善您的安全状态。 有关多阶段构建的更多信息，请参见https://docs.docker.com/develop/develop-images/multistage-build/.

### 定期扫描镜像中的漏洞
像它们的虚拟机副本一样，容器镜像可以包含具有漏洞的二进制文件和应用程序库，或者随着时间的推移而开发漏洞。 防范漏洞利用的最佳方法是使用镜像扫描仪定期扫描镜像。 可以按需扫描或按需扫描Amazon ECR中存储的镜像（24小时内一次）。 ECR当前利用[Clair]（https://github.com/quay/clair）一个开源镜像扫描解决方案。 扫描镜像后，结果将记录到EventBridge中ECR的事件流中。 您还可以从ECR控制台中查看扫描结果。 具有高或严重漏洞的镜像应删除或重建。 如果已部署的镜像出现漏洞，则应尽快将其更换。. 

知道在何处部署了带有漏洞的镜像对于确保环境安全至关重要。 尽管可以想象自己构建镜像跟踪解决方案，但是已经有一些商业产品可以提供此功能以及其他高级功能，包括:
+ [Anchore](https://docs.anchore.com/current/)
+ [Twistlock](https://www.twistlock.com/)
+ [Aqua](https://www.aquasec.com/)
+ [Kubei](https://github.com/Portshift/kubei)
    
Kubernetes验证webhook也可以用于验证镜像没有严重漏洞。 验证Webhook在Kubernetes API之前被调用。 它们通常用于拒绝不符合Webhook中定义的验证标准的请求。 [这](https://github.com/jicowan/ecr-validation-webhook)是一个无服务器Webhook的示例，该Webhook调用ECR describeImageScanFindings API来确定Pod是否正在提取具有严重漏洞的镜像。 如果发现漏洞，则拒绝该Pod，并返回包含CVE列表的消息作为事件.

### 为ECR存储库创建IAM策略
如今，组织在一个共享的AWS账户中拥有多个独立运行的开发团队已经很普遍。 如果这些团队不需要共享资产，则可能需要创建一组IAM策略，以限制对每个团队可以与之交互的存储库的访问。 实现此目的的一种好方法是使用ECR [namespaces](https://docs.aws.amazon.com/AmazonECR/latest/userguide/Repositories.html#repository-concepts)。 命名空间是将相似存储库组合在一起的一种方式。 例如，团队A的所有注册表都可以使用team-a /作为前缀，而团队B的所有注册表都可以使用team-b /作为前缀。 限制访问的策略可能如下所示: 
```json
{
"Version": "2012-10-17",
"Statement": [{
  "Sid": "AllowPushPull",
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::123456789012:role/<team_a_role_name>"
  },
  "Action": [
    "ecr:GetDownloadUrlForLayer",
    "ecr:BatchGetImage",
    "ecr:BatchCheckLayerAvailability",
    "ecr:PutImage",
    "ecr:InitiateLayerUpload",
    "ecr:UploadLayerPart",
    "ecr:CompleteLayerUpload"
  ],
  "Resource": [
    "arn:aws:ecr:region:123456789012:repository/team-a/*"
  ]
  }]
}
```
### 考虑使用ECR私有终端节点
ECR API具有公共终端结点。 因此，只要请求已由IAM验证并授权，便可以从Internet访问ECR注册表。 对于需要在群集VPC缺少Internet网关（IGW）的沙盒环境中进行操作的用户，可以为ECR配置专用终端结点。 通过创建专用终结点，您可以通过专用IP地址来专用访问ECR API，而不是通过Internet路由通信。 有关此主题的更多信息，请参见 https://docs.aws.amazon.com/AmazonECR/latest/userguide/vpc-endpoints.html.

### 为ECR实施终端结点策略
默认的终端结点策略用于允许访问区域内的所有ECR存储库。 这可能允许攻击者/内部人员通过将数据打包为容器镜像并将其推送到另一个AWS账户中的注册表来窃取数据。 减轻这种风险涉及创建一个终端结点策略，该策略限制API对ECR存储库的访问。 例如，以下策略允许您账户中的所有AWS原则对您以及您唯一的ECR存储库执行所有操作: 
```json 
{
    "Statement": [{
    "Sid": "LimitECRAccess",
    "Principal": "*",
    "Action": "*",
    "Effect": "Allow",
    "Resource": "arn:aws:ecr:region:<your_account_id>:repository/*"
    },
  ]
}
```
您可以通过设置使用新`PrincipalOrgID`属性的条件来进一步增强此条件，该条件将防止不属于您的AWS组织的IAM原理来推/拉镜像。 有关其他详细信息，请参见[aws:PrincipalOrgID](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-principalorgid). 

我们建议对`com.amazonaws.<region>.ecr.dkr`和`com.amazonaws.<region>.ecr.api`终端节点应用相同的策略。

由于EKS会从ECR提取kube-proxy，coredns和aws-node的镜像，因此您需要添加注册表的帐户ID，例如 将`602401143452.dkr.ecr.us-west-2.amazonaws.com/*`添加到终端结点策略中的资源列表，或更改策略以允许从"*" 中提取并限制对您帐户ID的推送。 下表显示了从中出售EKS镜像的AWS账户与集群区域之间的映射.

  | Account Number | 区域 |
  | -------------- | ------ |
  | 602401143452 | All commercial regions except for those listed below |
  | 800184023465 | HKG | 
  | 558608220178 | BAH |
  | 918309763551 | BJS | 
  | 961992271922 | ZHY |

有关使用终端节点策略的更多信息，请参阅[使用VPC终端节点策略控制Amazon ECR访问](https://aws.amazon.com/blogs/containers/using-vpc-endpoint-policies-to-control-amazon-ecr-access/). 

### 创建一组策展(curate)的镜像
与其允许开发人员创建自己的镜像，不如考虑为组织中的不同应用程序堆栈创建一组经过审查的镜像。这样，开发人员可以放弃学习如何编写Dockerfile的工作，而专注于编写代码。随着更改合并到Master中，CI / CD管道可以自动编译资产，将其存储在工件存储库中，并将工件复制到适当的镜像中，然后再将其推送到Docker注册表（如ECR）。至少您应该创建一组基础镜像，开发人员可以从中创建自己的Dockerfile。理想情况下，您要避免从Dockerhub中提取镜像，因为a）您并不总是知道镜像中的内容，b）关于1000个最常用的镜像的[五分之一](https://www.kennasecurity.com/blog/one-fifth-of-the-most-used-docker-containers-have-at-least-one-critical-vulnerability/)）都具有漏洞。这些镜像及其漏洞的列表可以在 https://vulnerablecontainers.org/ 找到。.

### 将USER指令添加到您的Dockerfile中以非root用户身份运行
如Pod安全性部分所述，您应避免以root用户身份运行容器。 虽然您可以将其配置为podSpec的一部分，但对Dockerfile使用`USER` 指令是一个好习惯。 `USER` 指令设置在USER指令之后的运行`RUN`, `ENTRYPOINT`或`CMD` 指令时要使用的UID.

### 整理你的Dockerfile
Linting可用于验证您的Dockerfile是否遵守一组预定义的准则，例如 包含“ USER”指令或要求标记所有镜像。 [dockerfile_lint](https://github.com/projectatomic/dockerfile_lint)是RedHat的一个开源项目，它验证了常见的最佳实践，并且包括一个规则引擎，您可以使用该规则引擎来构建自己的规则来添加Dockerfile。 可以将其合并到CI管道中，在该管道中使用违反规则的Dockerfile构建将自动失败. 

### 从头开始构建镜像
减少容器镜像的受攻击面应该是构建镜像时的主要目标。 做到这一点的理想方法是创建最小的镜像，这些镜像没有可用来利用漏洞的二进制文件。 幸运的是，Docker具有一种从[`scratch`](https://docs.docker.com/develop/develop-images/baseimages/#create-a-simple-parent-image-using-scratch)创建镜像的机制。 使用Go之类的语言，您可以创建一个静态链接的二进制文件，并在Dockerfile中引用它，如本例所示: 
```dockerfile
############################
# STEP 1 build executable binary
############################
FROM golang:alpine AS builder
# Install git.
# Git is required for fetching the dependencies.
RUN apk update && apk add --no-cache git
WORKDIR $GOPATH/src/mypackage/myapp/
COPY . .
# Fetch dependencies.
# Using go get.
RUN go get -d -v
# Build the binary.
RUN go build -o /go/bin/hello
############################
# STEP 2 build a small image
############################
FROM scratch
# Copy our static executable.
COPY --from=builder /go/bin/hello /go/bin/hello
# Run the hello binary.
ENTRYPOINT ["/go/bin/hello"]
```
这将创建一个包含应用程序和其他内容的容器镜像，从而使其极为安全.

### 对镜像签名
首次引入Docker时，还没有用于验证容器镜像的加密模型。在v2中，Docker将摘要添加到镜像清单中。这样就可以对图片的配置进行哈希处理，并且可以使用哈希值生成图片的ID。启用镜像签名后，\[Docker\] 引擎将验证清单的签名，以确保内容是从受信任的来源产生的，并且未发生篡改。下载每一层后，引擎将验证该层的摘要，以确保内容与清单中指定的内容匹配。镜像签名有效地使您可以通过验证与镜像关联的数字签名来创建安全的供应链。

在Kubernetes环境中，您可以使用动态准入控制器来验证镜像是否已签名，如以下示例所示： https://github.com/kelseyhightower/grafeas-tutorial 。通过对镜像进行签名，您正在验证发布者（源），以确保镜像未被篡改（完整性）.

## 工具
+ [Bane](https://github.com/genuinetools/bane)适用于Docker容器的AppArmor配置文件生成器
+ [docker-slim](https://github.com/docker-slim/docker-slim) 构建安全的最小镜像
+ [dockerfile-lint](https://github.com/projectatomic/dockerfile_lint) Dockerfile的基于规则的linter
+ [Gatekeeper and OPA](https://github.com/open-policy-agent/gatekeeper) 基于策略的准入控制器
+ [in-toto](https://in-toto.io/) 允许用户验证是否打算执行供应链中的某个步骤，以及该步骤是否由正确的参与者执行
+ [Notary](https://github.com/theupdateframework/notary) 签署容器镜像的项目
+ [Grafeas](https://grafeas.io/) 开放的工件元数据API，用于审核和管理软件供应链