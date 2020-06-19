# Pod 安全

Pods具有各种不同的设置，可以增强或削弱您的总体安全状况。 作为Kubernetes的从业者，您的主要担心应该是防止容器中运行的进程逃离Docker的隔离边界并获得对基础主机的访问权。 原因是双重的。 首先，默认情况下，在容器中运行的进程在\[Linux\] root用户的上下文中运行。 尽管容器中root用户的行为部分受到Docker分配给容器的Linux Capabilities的限制，但是这些默认特权可以使攻击者提升其特权和/或访问绑定到主机的敏感信息，包括Secrets 和ConfigMaps。 以下是分配给Docker容器的默认功能的列表。 有关每种功能的更多信息，请参见 http://man7.org/linux/man-pages/man7/capabilities.7.html.

`CAP_CHOWN, CAP_DAC_OVERERIDE, CAP_FOWNER, CAP_FSETID, CAP_KILL, CAP_SETGID, CAP_SETUID, CAP_SETPCAP, CAP_NET_BIND_SERVICE, CAP_NET_RAW, CAP_SYS_CHROOT, CAP_MKNOD, CAP_AUDIT_WRITE, CAP_SETFCAP`

!!! 信息 
    EC2和Fargate pods默认分配了上述功能。 此外，只能从Fargate Pod中删除Linux Capabilities. 

以特权身份运行的Pod会继承与主机上的root关联的Linux Capabilities的 _所有_ 功能，因此应尽可能避免使用。

其次，所有Kubernetes工作者节点都使用一种称为节点授权者的授权模式。 节点授权者授权所有来自kubelet的API请求，并允许节点执行以下操作: 

读取操作:

+ services
+ endpoints
+ nodes
+ pods
+ secrets, configmaps,持久卷声明 和持久卷与关联到已经绑定到kubelet节点的Pod

写操作:

+ nodes and node status (启用`NodeRestriction`接纳插件以限制kubelet修改自己的节点)
+ pods and pod status (启用`NodeRestriction`接纳插件以限制kubelet修改绑定到其自身的pod)
+ events

与验证相关的操作:

+ 对TLS引导的对CertificateSigningRequest（CSR）API的读/写访问权限
+ 创建TokenReview和SubjectAccessReview进行委托的身份验证/授权检查的能力

EKS使用[节点限制准入控制器](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#noderestriction) 这仅允许节点修改绑定到该节点的节点属性和pod对象的有限集合。 尽管如此，设法访问主机的攻击者仍将能够从Kubernetes API中收集有关环境的敏感信息，从而使他们可以在集群内横向移动。.

## 推荐建议

### 限制可以特权运行的容器
如前所述，以特权身份运行的容器会继承分配给主机根用户的所有Linux Capabilities。 容器很少需要这些类型的特权才能正常运行。 您可以通过创建一个[pod security policy](https://kubernetes.io/docs/concepts/policy/pod-security-policy/) 来拒绝运行具有配置为以特权方式运行的容器的pod.  您可以将Pod安全策略视为Pod在创建之前必须满足的一组要求。 如果选择使用Pod安全策略，则需要创建一个角色绑定，以允许服务帐户读取您的Pod安全策略. 

当您配置EKS集群时，会自动创建一个名为`eks.privileged`的Pod安全策略。 该政策的清单显示在下面: 

```yaml
apiVersion: extensions/v1beta1
kind: PodSecurityPolicy
metadata:
  annotations:
    kubernetes.io/description: privileged allows full unrestricted access to pod features,
      as if the PodSecurityPolicy controller was not enabled.
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: '*'
  labels:
    eks.amazonaws.com/component: pod-security-policy
    kubernetes.io/cluster-service: "true"
  name: eks.privileged
spec:
  allowPrivilegeEscalation: true
  allowedCapabilities:
  - '*'
  fsGroup:
    rule: RunAsAny
  hostIPC: true
  hostNetwork: true
  hostPID: true
  hostPorts:
  - max: 65535
    min: 0
  privileged: true
  runAsUser:
    rule: RunAsAny
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  volumes:
  - '*'
```

此PSP允许经过身份验证的用户在群集中的所有名称空间上运行特权容器。 乍一看，这似乎过于宽松，但某些应用程序/插件（例如AWS VPC CNI和kube-proxy）必须以特权身份运行，因为它们负责配置主机的网络设置。 此外，该策略提供了与缺乏对pod安全策略的支持的Kubernetes早期版本的向后兼容性。.    

下面显示的绑定是将ClusterRole`eks:podsecuritypolicy:privileged` 绑定到`system:authenticated`  RBAC组. 

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  annotations: 
    kubernetes.io/description: Allow all authenticated users to create privileged
  labels:
    eks.amazonaws.com/component: pod-security-policy
    kubernetes.io/cluster-service: "true"
  name: eks:podsecuritypolicy:authenticated
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: eks:podsecuritypolicy:privileged
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: Group
  name: system:authenticated
```

最后，下面的ClusterRole允许所有引用它的绑定都使用`eks.privileged` PodSecurityPolicy。

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
    eks.amazonaws.com/component: pod-security-policy
    kubernetes.io/cluster-service: "true"
  name: eks:podsecuritypolicy:privileged
rules:
- apiGroups:
  - policy
  resourceNames:
  - eks.privileged
  resources:
  - podsecuritypolicies
  verbs:
  - use
``` 

最佳做法是，建议您将特权Pod的绑定范围限定在特定名称空间（例如， kube系统，并限制对该名称空间的访问。 对于所有其他服务帐户/命名空间，我们建议实施限制性更强的策略，例如: 

```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
    name: restricted
    annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: 'docker/default,runtime/default'
    apparmor.security.beta.kubernetes.io/allowedProfileNames: 'runtime/default'
    seccomp.security.alpha.kubernetes.io/defaultProfileName:  'runtime/default'
    apparmor.security.beta.kubernetes.io/defaultProfileName:  'runtime/default'
spec:
    privileged: false
    # Required to prevent escalations to root.
    allowPrivilegeEscalation: false
    # This is redundant with non-root + disallow privilege escalation,
    # but we can provide it for defense in depth.
    requiredDropCapabilities:
    - ALL
    # Allow core volume types.
    volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    # Assume that persistentVolumes set up by the cluster admin are safe to use.
    - 'persistentVolumeClaim'
    hostNetwork: false
    hostIPC: false
    hostPID: false
    runAsUser:
    # Require the container to run without root privileges.
    rule: 'MustRunAsNonRoot'
    seLinux:
    # This policy assumes the nodes are using AppArmor rather than SELinux.
    rule: 'RunAsAny'
    supplementalGroups:
    rule: 'MustRunAs'
    ranges:
        # Forbid adding the root group.
        - min: 1
        max: 65535
    fsGroup:
    rule: 'MustRunAs'
    ranges:
        # Forbid adding the root group.
        - min: 1
        max: 65535
    readOnlyRootFilesystem: false
```

此策略可防止Pod作为特权或升级特权运行。 它还限制了可以安装的卷的类型和可以添加的根补充组。. 

另一种尽管相似的方法是从锁定所有内容的策略开始，然后为需要更宽松限制的应用程序（例如需要安装主机路径能力的日志记录代理）添加增量例外。 您可以在[Square engineering blog](https://developer.squareup.com/blog/kubernetes-pod-security-policies/)上的最新帖子中了解有关此内容的更多信息.

!!! 注意 
    Fargate是一种启动类型，可让您运行 "serverless" 容器，其中pod的容器在AWS管理的基础架构上运行。 使用Fargate，您无法运行特权容器或将pod配置为使用hostNetwork或hostPort.

### 不要以根用户身份在容器中运行进程
默认情况下，所有容器都以root用户身份运行。 如果攻击者能够利用应用程序中的漏洞并使外壳程序访问运行中的容器，则可能会出现问题。 您可以通过多种方式减轻这种风险。 首先，通过从容器映像中删除外壳。 其次，将USER指令添加到Dockerfile或以非root用户身份运行pod中的容器。 Kubernetes podSpec在`spec.securityContext`下包含一组字段，这些字段允许您指定用户和/或组来运行您的应用程序。 这些字段分别是`runAsUser`和`runAsGroup`。 您可以通过创建Pod安全策略来强制使用这些字段.  阅读 https://kubernetes.io/docs/concepts/policy/pod-security-policy/#users-and-groups 获得有关此主题的更多信息。

### 切勿在Docker中运行Docker 或将套接字安装在容器中
尽管这使您可以方便地在Docker容器中构建/运行映像，但是基本上是将节点的完全控制权交给了容器中运行的进程。 如果您需要在Kubernetes上构建容器映像，请使用 [Kaniko](https://github.com/GoogleContainerTools/kaniko), [buildah](https://github.com/containers/buildah), [img](https://github.com/genuinetools/img), 或类似 [CodeBuild](https://docs.aws.amazon.com/codebuild/latest/userguide/welcome.html) 的构建服务来代替. 

### 限制使用hostPath，或者如果需要hostPath，限制可以使用的前缀并将卷配置为只读
`hostPath`是将目录从主机直接装载到容器的卷。 吊舱很少需要这种类型的访问权限，但如果确实需要，则需要意识到风险。 默认情况下，以root用户身份运行的Pod将具有对hostPath公开的文件系统的写访问权。 这可能允许攻击者修改kubelet设置，创建指向目录或文件的符号链接，这些目录或文件未直接由hostPath公开。 /etc/shadow，安装ssh密钥，读取安装到主机的机密以及其他恶意内容。 为了减轻hostPath带来的风险，例如，将`spec.containers.volumeMounts`配置为readOnly。: 

```yaml
volumeMounts:
- name: hostPath-volume
    readOnly: true
    mountPath: /host-path
```

您还应该使用Pod安全策略来限制hostPath卷可以使用的目录。 例如，以下PSP摘录仅允许以`/foo`开头的路径。 这将防止容器从前缀之外遍历主机文件系统。: 

```yaml
allowedHostPaths:
# This allows "/foo", "/foo/", "/foo/bar" etc., but
# disallows "/fool", "/etc/foo" etc.
# "/foo/../" is never valid.
- pathPrefix: "/foo"
    readOnly: true # only allow read-only mounts
```

### 为每个容器设置请求和限制，以避免资源争用和DoS攻击
理论上，没有请求或限制的Pod可以消耗主机上所有可用的资源。 随着其他Pod被调度到一个节点上，该节点可能会经历CPU或内存压力，这可能会导致Kubelet终止或从该节点逐出Pod。 虽然您无法阻止这一切同时发生，但是设置请求和限制将有助于最大程度地减少资源争用，并减轻编写质量差的应用程序占用大量资源的风险. 

`podSpec` 允许您指定CPU和内存的请求和限制。 CPU被认为是可压缩资源，因为它可能被超额订购。 内存不可压缩，即无法在多个容器之间共享.  

当您指定对CPU或内存的 _请求_ 时，实际上是在指定要保证容器获得的 _内存_ 数量。 Kubernetes汇总Pod中所有容器的请求，以确定将Pod调度到哪个节点上。 如果容器超出了请求的内存量，则如果节点上存在内存压力，则可能会终止该容器. 

_Limits_ 是允许容器消耗的CPU和内存资源的最大数量，直接与为容器创建的cgroup的`memory.limit_in_bytes`值相对应。 超出内存限制的容器将被OOM杀死。 如果容器超出其CPU限制，则会受到限制. 

Kubernetes使用三种服务质量（QoS）类对节点上运行的工作负载进行优先级排序。 其中包括：保证，可突破和尽力而为。 如果未设置限制和请求，则将窗格配置为尽力而为（最低优先级）。 当内存不足时，尽力而为的pod是第一个被杀死的pod。 如果对容器中的 _所有_ 容器设置了限制，或者将请求和限制设置为相同的值且不等于0，则将容器配置为保证（最高优先级）。 除非已保证的Pod超出其配置的内存限制，否则不会杀死它们。 如果将限制和请求配置为不同的值且不等于0，或者pod容器中的一个容器设置了限制，而其他容器没有或为不同资源设置了限制，则将pod配置为可爆裂（中等优先级）。 这些Pod有一定的资源保证，但是一旦超过请求的内存量就可以杀死它们。. 

!!! 注意
    请求不会影响容器的cgroup的 `memory_limit_in_bytes`值； cgroup限制设置为主机上可用的内存量。 但是，如果节点的内存压力过大，则将请求值设置得太低可能会导致pod被kubelet终止. 

| 类别 | 优先级 | 条件 | 终止条件 |
| :-- | :-- | :-- | :-- |
| Guaranteed 保证的 | 最高 | limit = request != 0  | 仅超出内存限制 |
| Burstable 可突破 | 中  | limit != request != 0 | 如果超出请求内存，可能会被杀死 |
| Best-Effort 尽力而为| 低  | limit & request Not Set | 当内存不足时首先被杀死 |

有关资源QoS的其他信息，请参阅  [Kubernetes documentation](https://github.com/kubernetes/community/blob/master/contributors/design-proposals/node/resource-qos.md).

您可以通过在名称空间上设置[资源配额](https://kubernetes.io/docs/concepts/policy/resource-quotas/)或通过创建[限制范围](https://kubernetes.io/docs/concepts/policy/limit-range/). 资源配额可让您指定资源总量，例如 CPU和RAM，分配给名称空间。 将其应用于名称空间后，它会强制您为部署到该名称空间的所有容器指定请求和限制。 相反，限制范围使您可以更精细地控制资源分配。 使用限制范围，您可以为名称空间内每个容器或每个容器的CPU和内存资源最小/最大。 如果未提供默认请求/限制值，也可以使用它们来设置默认值。

### 不允许特权升级
特权升级允许进程更改其运行所在的安全上下文。 Sudo和SUID或SGID位的二进制文件就是一个很好的例子。 特权升级基本上是用户在另一个用户或组的许可下执行文件的方式。 您可以通过实施将PodSpec中的`allowPriviledgedEscalation`设置为`false`的pod安全策略，或通过在`podSpec`.中设置`securityContext.allowPrivilegedEscalation`来阻止容器使用特权升级。

## 工具
+ [kube-psp-advisor](https://github.com/sysdiglabs/kube-psp-advisor) 是一种工具，可让您更轻松地从实时K8s环境或包含一个Pod规范（Deployment，DaemonSet，Pod等）的单个.yaml文件创建K8s Pod安全策略（PSP）。
