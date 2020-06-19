# Identity and Access Management 身份和访问管理
[Identity and Access Management](https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction.html) (IAM) 是执行两项基本功能的AWS服务：身份验证和授权。 身份验证涉及身份验证，而授权则控制可以由AWS资源执行的操作.  在AWS中，资源可以是另一个AWS服务，例如 EC2或AWS [principle](https://docs.aws.amazon.com/IAM/latest/UserGuide/intro-structure.html#intro-structure-principal) 例如一个 [IAM User](https://docs.aws.amazon.com/IAM/latest/UserGuide/id.html#id_iam-users) 或者 [Role](https://docs.aws.amazon.com/IAM/latest/UserGuide/id.html#id_iam-roles).  管理资源允许执行的操作的规则表示为 [IAM policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html).  

## 控制对EKS集群的访问
Kubernetes项目支持多种不同的策略来验证对kube-apiserver服务的请求，例如 承载令牌，X.509证书，OIDC等。EKS当前原生支持 [webhook token authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#webhook-token-authentication) 和[service account tokens](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#service-account-tokens).  

Webhook身份验证策略调用一个Webhook，以验证承载令牌。 在EKS上，这些承载令牌是由AWS CLI或 [aws-iam-authenticator](https://github.com/kubernetes-sigs/aws-iam-authenticator) 客户端运行`kubectl`命令。 在执行命令时，令牌将传递到kube-apiserver，该服务器将其转发到身份验证Webhook。 如果请求格式正确，则Webhook会调用嵌入在令牌主体中的预签名URL。 该URL验证请求的签名并返回有关用户的信息，例如 用户的帐户Arn和UserId到kube-apiserver。

要手动生成身份验证令牌，请在终端窗口中键入以下命令: 
```bash
aws eks get-token --cluster <cluster_name>
```
输出应类似于此: 
```json
{
  "kind": "ExecCredential", 
  "apiVersion": "client.authentication.k8s.io/v1alpha1", 
  "spec": {}, 
  "status": {
    "expirationTimestamp": "2020-02-19T16:08:27Z", 
    "token": "k8s-aws-v1.aHR0cHM6Ly9zdHMuYW1hem9uYXdzLmNvbS8_QWN0aW9uPUdldENhbGxlcklkZW50aXR5JlZlcnNpb249MjAxMS0wNi0xNSZYLUFtei1BbGdvcml0aG09QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsPUFLSUFKTkdSSUxLTlNSQzJXNVFBJTJGMjAyMDAyMTklMkZ1cy1lYXN0LTElMkZzdHMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDIwMDIxOVQxNTU0MjdaJlgtQW16LUV4cGlyZXM9NjAmWC1BbXotU2lnbmVkSGVhZGVycz1ob3N0JTNCeC1rOHMtYXdzLWlkJlgtQW16LVNpZ25hdHVyZT0yMjBmOGYzNTg1ZTMyMGRkYjVlNjgzYTVjOWE0MDUzMDFhZDc2NTQ2ZjI0ZjI4MTExZmRhZDA5Y2Y2NDhhMzkz"
  }
}
```
每个令牌均以“ k8s-aws-v1”开头，后跟base64编码的字符串。 字符串在解码时应类似于此: 
```bash
https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAJPFRILKNSRC2W5QA%2F20200219%2Fus-east-1%2Fsts%2Faws4_request&X-Amz-Date=20200219T155427Z&X-Amz-Expires=60&X-Amz-SignedHeaders=host%3Bx-k8s-aws-id&X-Amz-Signature=220f8f3285e320ddb5e683a5c9a405301ad76546f24f28111fdad09cf648a393
```
令牌由包含Amazon凭证和签名的预签名URL组成。 有关更多详细信息，请参见https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html. 

令牌的生存时间（TTL）为15分钟，之后需要生成新令牌。 当您使用类似`kubectl`这样的客户端时，会自动处理该问题，但是，如果您使用的是Kubernetes仪表板，则每次令牌到期时都需要生成一个新令牌并重新进行身份验证. 

一旦用户的身份已通过AWS IAM服务进行身份验证，kube-apiserver就会在“ kube-system”命名空间中读取“ aws-auth” ConfigMap，以确定要与用户关联的RBAC组。 aws-auth ConfigMap用于在IAM原则（即IAM用户和角色）与Kubernetes RBAC组之间创建静态映射。 可以在Kubernetes RoleBindings或ClusterRoleBindings中引用RBAC组。 它们与IAM角色相似，因为它们定义了可以对Kubernetes资源（对象）的集合执行的一组动作（动词）。

## 推荐建议

### 不要使用服务帐户令牌进行身份验证
服务帐户令牌是长期存在的静态证书。 如果它被泄露，丢失或被盗，攻击者可能能够执行与该令牌相关的所有操作，直到删除该服务帐户为止。 有时，您可能需要为必须从集群外部使用Kubernetes API的应用程序授予例外，例如 CI / CD管道应用程序。 如果此类应用程序在AWS基础设施（例如EC2实例）上运行，请考虑使用实例配置文件并将其映射到“ aws-auth” ConfigMap中的Kubernetes RBAC角色。

### 使用对AWS资源的最低特权访问
无需为IAM用户分配AWS资源的特权即可访问Kubernetes API。 如果您需要授予IAM用户访问EKS集群的权限，请在“ aws-auth” ConfigMap中为该用户创建一个条目，该条目映射到特定的Kubernetes RBAC组。 

### 当多个用户需要对群集的相同访问权限时，请使用IAM角色
与其在aws-auth ConfigMap中为每个IAM用户创建一个条目，不如让这些用户承担IAM角色并将该角色映射到Kubernetes RBAC组。 这将更易于维护，尤其是随着需要访问的用户数量的增长。

### 创建RoleBindings和ClusterRoleBindings时，采用最少特权的访问
就像之前有关授予对AWS资源的访问权限的观点一样，RoleBindings和ClusterRoleBindings应该仅包括执行特定功能所需的一组权限。 除非绝对必要，否则请避免在Roles和ClusterRoles中使用`["*"]` 。 如果不确定要分配什么权限，请考虑使用类似的工具 [audit2rbac](https://github.com/liggitt/audit2rbac) 来根据Kubernetes审核日志中观察到的API调用自动生成角色和绑定.

### 将EKS集群端点设为私有
默认情况下，当您配置EKS群集时，API群集终结点设置为public，即可以从Internet访问它。 尽管可以从Internet进行访问，但该端点仍被认为是安全的，因为它要求所有API请求均由IAM进行身份验证，然后由Kubernetes RBAC授权。 也就是说，如果您的公司安全策略要求您限制从Internet访问API或阻止您将流量路由到群集VPC之外，则可以: 

+ 将EKS集群端点配置为私有。 阅读 [Modifying Cluster Endpoint Access](https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html) 有关此主题的更多信息. 
+ 使群集端点公开，并指定哪些CIDR块可以与群集端点进行通信。 这些块实际上是一组白名单的公共IP地址，允许访问群集端点.
+ 使用一组列入白名单的CIDR块配置公共访问，并将私有端点访问设置为启用。 这将允许从特定范围的公共IP进行公共访问，同时通过配置控制平面时被配置到集群VPC中的跨帐户ENI强制Kubelet（工作节点）和Kubernetes API之间的所有网络流量。.

### 定期审核对集群的访问
谁需要访问权限可能会随时间变化。 计划定期审核 `aws-auth` ConfigMap，以查看授予了谁访问权限以及他们的权限。 您还可以使用开源工具，例如 [kubectl-who-can](https://github.com/aquasecurity/kubectl-who-can), 或者 [rbac-lookup](https://github.com/FairwindsOps/rbac-lookup) 检查绑定到特定服务帐户，用户或组的角色。 当我们转到以下部分[auditing](detective.md)时，我们将进一步探讨该主题。 .  其他想法可以在这里找到 [article](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2019/august/tools-and-methods-for-auditing-kubernetes-rbac-policies/?mkt_tok=eyJpIjoiWWpGa056SXlNV1E0WWpRNSIsInQiOiJBT1hyUTRHYkg1TGxBV0hTZnRibDAyRUZ0VzBxbndnRzNGbTAxZzI0WmFHckJJbWlKdE5WWDdUQlBrYVZpMnNuTFJ1R3hacVYrRCsxYWQ2RTRcL2pMN1BtRVA1ZFZcL0NtaEtIUDdZV3pENzNLcE1zWGVwUndEXC9Pb2tmSERcL1pUaGUifQ%3D%3D) from NCC Group. 

### 身份验证和访问管理的替代方法
虽然IAM是对需要访问EKS集群的用户进行身份验证的首选方法，但可以使用OIDC身份提供程序（例如GitHub）使用身份验证代理和Kubernetes [impersonation](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation). 两种此类解决方案的帖子已发布在AWS Open Source博客上：

+ [使用带有Teleport的GitHub凭证对EKS进行身份验证](https://aws.amazon.com/blogs/opensource/authenticating-eks-github-credentials-teleport/)
+ [使用kube-oidc-proxy跨多个EKS集群进行一致的OIDC身份验证](https://aws.amazon.com/blogs/opensource/consistent-oidc-authentication-across-multiple-eks-clusters-using-kube-oidc-proxy/)

您也可以使用 [AWS SSO](https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html) 将AWS与外部身份提供商联合起来 Azure AD。 如果您决定使用此选项，则AWS CLI v2.0包含一个用于创建命名配置文件的选项，该选项使轻松将SSO会话与当前的CLI会话关联并承担IAM角色。 知道你必须切换到一个角色 _之前_ 来运行 `kubectl` 因为IAM角色用于确定用户的Kubernetes RBAC组.

## Pods 身份
在Kubernetes集群中运行的某些应用程序需要权限才能调用Kubernetes API才能正常运行。 例如， [ALB Ingress Controller](https://kubernetes-sigs.github.io/aws-alb-ingress-controller/) 需要能够列出服务的终端节点。 控制器还需要能够调用AWS API来配置和配置ALB。 在本节中，我们将探讨为Pod分配权限的最佳实践。

### Kubernetes服务帐号
服务帐户是一种特殊的对象类型，它允许您将Kubernetes RBAC角色分配给Pod。 将自动为集群中的每个命名空间创建一个默认服务帐户。 当您将Pod部署到命名空间而不引用特定服务帐户时，该命名空间的默认服务帐户将自动分配给Pod和Secret，即该服务帐户的服务帐户（JWT）令牌将被安装到 在`/var/run/secrets/kubernetes.io/serviceaccount`上将Pod作为卷。 对该目录中的服务帐户令牌进行解码将显示以下元数据： 
```json
{
  "iss": "kubernetes/serviceaccount",
  "kubernetes.io/serviceaccount/namespace": "default",
  "kubernetes.io/serviceaccount/secret.name": "default-token-5pv4z",
  "kubernetes.io/serviceaccount/service-account.name": "default",
  "kubernetes.io/serviceaccount/service-account.uid": "3b36ddb5-438c-11ea-9438-063a49b60fba",
  "sub": "system:serviceaccount:default:default"
}
``` 

默认服务帐户对Kubernetes API具有以下权限.
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  annotations:
    rbac.authorization.kubernetes.io/autoupdate: "true"
  creationTimestamp: "2020-01-30T18:13:25Z"
  labels:
    kubernetes.io/bootstrapping: rbac-defaults
  name: system:discovery
  resourceVersion: "43"
  selfLink: /apis/rbac.authorization.k8s.io/v1/clusterroles/system%3Adiscovery
  uid: 350d2ab8-438c-11ea-9438-063a49b60fba
rules:
- nonResourceURLs:
  - /api
  - /api/*
  - /apis
  - /apis/*
  - /healthz
  - /openapi
  - /openapi/*
  - /version
  - /version/
  verbs:
  - get
```
此角色授权未经身份验证和身份验证的用户读取API信息，并且可以安全地公开访问.

当在Pod中运行的应用程序调用Kubernetes API时，需要为Pod分配一个服务帐户，该服务帐户明确授予其调用这些API的权限。 与用户访问准则相似，绑定到服务帐户的Role或ClusterRole应该限制为应用程序需要运行的API资源和方法，而没有其他限制。 要使用非默认服务帐户，只需将Pod的`spec.serviceAccountName` 字段设置为您要使用的服务帐户的名称即可。 有关创建服务帐户的其他信息，请参阅 https://kubernetes.io/docs/reference/access-authn-authz/rbac/#service-account-permissions. 

### 服务帐户的IAM角色 (IRSA)
IRSA是一项功能，允许您将IAM角色分配给Kubernetes服务帐户。 它通过利用称为[服务帐户令牌数量预测](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#service-account-token-volume-projection)的Kubernetes功能来工作。 具有引用IAM角色的服务帐户的Pod在启动时将调用AWS IAM的公共OIDC发现终端节点。 端点通过密码签名由Kubernetes发行的OIDC令牌，该令牌最终允许Pod调用与AWS API相关的IAM角色。 调用AWS API时，AWS开发工具包会调用`sts:AssumeRoleWithWebIdentity`，并自动将Kubernetes发行的令牌交换为AWS角色证书。. 

解码IRSA的（JWT）令牌将产生类似于您在下面看到的示例的输出: 
```json
{
  "aud": [
    "sts.amazonaws.com"
  ],
  "exp": 1582306514,
  "iat": 1582220114,
  "iss": "https://oidc.eks.us-west-2.amazonaws.com/id/D43CF17C27A865933144EA99A26FB128",
  "kubernetes.io": {
    "namespace": "default",
    "pod": {
      "name": "alpine-57b5664646-rf966",
      "uid": "5a20f883-5407-11ea-a85c-0e62b7a4a436"
    },
    "serviceaccount": {
      "name": "s3-read-only",
      "uid": "a720ba5c-5406-11ea-9438-063a49b60fba"
    }
  },
  "nbf": 1582220114,
  "sub": "system:serviceaccount:default:s3-read-only"
}
```
此特定令牌向S3授予Pod只读权限。 当应用程序尝试从S3读取数据时，将令牌交换为类似于以下内容的IAM临时凭证集: 
```json
{
    "AssumedRoleUser": {
        "AssumedRoleId": "AROA36C6WWEJULFUYMPB6:abc", 
        "Arn": "arn:aws:sts::123456789012:assumed-role/eksctl-winterfell-addon-iamserviceaccount-de-Role1-1D61LT75JH3MB/abc"
    }, 
    "Audience": "sts.amazonaws.com", 
    "Provider": "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/D43CF17C27A865933144EA99A26FB128", 
    "SubjectFromWebIdentityToken": "system:serviceaccount:default:s3-read-only", 
    "Credentials": {
        "SecretAccessKey": "ORJ+8Adk+wW+nU8FETq7+mOqeA8Z6jlPihnV8hX1", 
        "SessionToken": "FwoGZXIvYXdzEGMaDMLxAZkuLpmSwYXShiL9A1S0X87VBC1mHCrRe/pB2oes+l1eXxUYnPJyC9ayOoXMvqXQsomq0xs6OqZ3vaa5Iw1HIyA4Cv1suLaOCoU3hNvOIJ6C94H1vU0siQYk7DIq9Av5RZe+uE2FnOctNBvYLd3i0IZo1ajjc00yRK3v24VRq9nQpoPLuqyH2jzlhCEjXuPScPbi5KEVs9fNcOTtgzbVf7IG2gNiwNs5aCpN4Bv/Zv2A6zp5xGz9cWj2f0aD9v66vX4bexOs5t/YYhwuwAvkkJPSIGvxja0xRThnceHyFHKtj0H+bi/PWAtlI8YJcDX69cM30JAHDdQH+ltm/4scFptW1hlvMaP+WReCAaCrsHrAT+yka7ttw5YlUyvZ8EPog+j6fwHlxmrXM9h1BqdikomyJU00gm1++FJelfP+1zAwcyrxCnbRl3ARFrAt8hIlrT6Vyu8WvWtLxcI8KcLcJQb/LgkW+sCTGlYcY8z3zkigJMbYn07ewTL5Ss7LazTJJa758I7PZan/v3xQHd5DEc5WBneiV3iOznDFgup0VAMkIviVjVCkszaPSVEdK2NU7jtrh6Jfm7bU/3P6ZG+CkyDLIa8MBn9KPXeJd/y+jTk5Ii+fIwO/+mDpGNUribg6TPxhzZ8b/XdZO1kS1gVgqjXyVC+M+BRBh6C4H21w/eMzjCtDIpoxt5rGKL6Nu/IFMipoC4fgx6LIIHwtGYMG7SWQi7OsMAkiwZRg0n68/RqWgLzBt/4pfjSRYuk=", 
        "Expiration": "2020-02-20T18:49:50Z", 
        "AccessKeyId": "ASIA36C6WWEJUMHA3L7Z"
    }
}
```  

作为EKS控制平面一部分运行的变异Webhook将AWS Role ARN和Web身份令牌文件的路径作为环境变量注入Pod。 这些值也可以手动提供. 
```
AWS_ROLE_ARN=arn:aws:iam::AWS_ACCOUNT_ID:role/IAM_ROLE_NAME
AWS_WEB_IDENTITY_TOKEN_FILE=/var/run/secrets/eks.amazonaws.com/serviceaccount/token
```

当kubelet超过其总TTL的80％时或24小时后，它将自动轮换投射的令牌。 当令牌轮换时，AWS开发工具包负责重新加载令牌。 有关IRSA的更多信息，请参见 https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts-technical-overview.html.

## 推荐建议

### 禁用服务帐户令牌的自动挂载
如果您的应用程序不需要调用Kubernetes API，则在您的应用程序的PodSpec中将`automountServiceAccountToken`属性设置为`false`或修补每个命名空间中的默认服务帐户，以使其不再自动挂载到Pod。 例如: 
```bash 
kubectl patch serviceaccount default -p $'automountServiceAccountToken: false'
```

### 为每个应用程序使用专用的服务帐户
每个应用程序应具有其自己的专用服务帐户。 这适用于Kubernetes API和IRSA的服务帐户. 

!!! 注意
   如果您采用蓝色/绿色方法进行群集升级，而不是执行就地替换集群升级，则需要使用新群集的OIDC端点更新每个IRSA IAM角色的信任策略。 蓝色/绿色集群升级是在其中创建一个与旧集群一起运行较新版本的Kubernetes的集群，并使用负载平衡器或服务网格将流量从旧集群上运行的服务无缝转移到新集群上。. 

### 限制对分配给工作节点的实例配置文件的访问
使用IRSA时，Pod不再继承分配给工作程序节点的实例配置文件的权限。 尽管如此，作为额外的预防措施，您可能希望阻止流程访问 [instance metadata](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html). 这将有效地防止不使用IRSA的Pod继承分配给工作节点的角色。 请注意，当您阻止访问工作程序节点上的实例元数据时，它可能会阻止某些Pod正常运行。 有关如何阻止访问实例元数据的其他信息，请参见 https://docs.aws.amazon.com/eks/latest/userguide/restrict-ec2-credential-access.html.

### 以非root用户身份运行应用程序
默认情况下，容器以root身份运行。 尽管这使他们能够读取Web标识令牌文件，但将容器作为root用户运行不是最佳实践。 作为替代方案，考虑将`spec.securityContext.runAsUser`属性添加到PodSpec。 runAsUser的值是缩写值.

在下面的示例中，Pod中的所有进程将在`runAsUser`字段中指定的用户ID下运行. 

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: security-context-demo
spec:
  securityContext:
    runAsUser: 1000
    runAsGroup: 3000
  containers:
  - name: sec-ctx-demo
    image: busybox
    command: [ "sh", "-c", "sleep 1h" ]
```

### 将IRSA的IAM角色信任策略的范围限定到服务帐户名
信任策略的范围可以是名称空间或名称空间内的特定服务帐户。 使用IRSA时，最好通过包含服务帐户名来使角色信任策略尽可能明确。 这将有效地防止同一命名空间中的其他Pod担任该角色。 当使用CLI `eksctl`创建服务帐户/ IAM角色时，它将自动执行此操作。 阅读 https://eksctl.io/usage/iamserviceaccounts/ 了解更多信息. 

### 替代方法
虽然IRSA是将AWS "identity" 分配给Pod的 _首选方法_，但它要求您在应用程序中包括最新版本的AWS开发工具包。 有关当前支持IRSA的SDK的完整列表，请参见 https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts-minimum-sdk.html. 如果您的应用程序无法立即使用与IRSA兼容的SDK进行更新，则可以使用多种社区构建的解决方案将IAM角色分配给Kubernetes Pod，包括 [kube2iam](https://github.com/jtblin/kube2iam) 和 [kiam](https://github.com/uswitch/kiam).  尽管AWS不认可或纵容这些解决方案的使用，但整个社区经常使用它们来获得与IRSA类似的结果. 
