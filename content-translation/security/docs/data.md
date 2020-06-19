# 静态加密
Kubernetes可以使用三种不同的AWS本地存储选项：[EBS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AmazonEBS.html)，[EFS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AmazonEFS.html)和[FSx for Lustre](https://docs.aws.amazon.com/fsx/latest/LustreGuide/what-is.html) 。所有这三个都使用服务管理密钥或客户主密钥（CMK）提供静态加密。对于EBS，您可以使用树中存储驱动程序或[EBS CSI驱动程序](https://github.com/kubernetes-sigs/aws-ebs-csi-driver)。两者都包含用于加密卷和提供CMK的参数。对于EFS，可以使用[EFS CSI驱动程序]（(https://github.com/kubernetes-sigs/aws-efs-csi-driver)，但是，与EBS不同，EFS CSI驱动程序不支持动态配置。如果要将EFS与EKS一起使用，则需要在创建PV之前为文件系统配置和配置静态加密。有关EFS文件加密的更多信息，请参阅[加密静态数据](https://docs.aws.amazon.com/efs/latest/ug/encryption-at-rest.html)。除了提供静态加密外，用于Luster的EFS和FSx还包括用于加密传输中数据的选项。 FSx for Luster默认情况下会执行此操作。对于EFS，您可以通过在PV中的`mountOptions` 中添加`tls` 参数来添加传输加密，如本例所示: 

```yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: efs-pv
spec:
  capacity:
    storage: 5Gi
  volumeMode: Filesystem
  accessModes:
    - ReadWriteOnce
  persistentVolumeReclaimPolicy: Retain
  storageClassName: efs-sc
  mountOptions:
    - tls
  csi:
    driver: efs.csi.aws.com
    volumeHandle: <file_system_id>
```

[FSx CSI驱动程序](https://github.com/kubernetes-sigs/aws-fsx-csi-driver)支持动态配置Lustre文件系统。 默认情况下，它使用服务管理密钥对数据进行加密，尽管如本例所示，可以选择提供自己的CMK:

```yaml
kind: StorageClass
apiVersion: storage.k8s.io/v1
metadata:
  name: fsx-sc
provisioner: fsx.csi.aws.com
parameters:
  subnetId: subnet-056da83524edbe641
  securityGroupIds: sg-086f61ea73388fb6b
  deploymentType: PERSISTENT_1
  kmsKeyId: <kms_arn>
``` 
!!! 注意
   截至2020年5月28日，默认情况下，将使用行业标准AES-256加密算法对写入EKS Fargate临时磁盘中临时卷的所有数据进行加密。 无需修改您的应用程序，因为服务可以无缝处理加密和解密. 

## 推荐建议
### 加密静态数据
加密静态数据被认为是最佳做法。 如果不确定是否需要加密，请加密数据. 

### 定期轮换您的CMK
配置KMS以自动轮换CMK。 这将每年轮换一次密钥，同时无限期保存旧密钥，以便仍可以解密您的数据。 有关更多信息，请参见[轮换客户主密钥](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html)

### 使用EFS访问点简化对共享数据集的访问
如果您拥有具有不同POSIX文件权限的共享数据集，或者想通过创建不同的安装点来限制对部分共享文件系统的访问，请考虑使用EFS访问点。 要了解有关使用访问点的更多信息，请参阅 https://docs.aws.amazon.com/efs/latest/ug/efs-access-points.html  今天，如果要使用接入点（AP），则需要在PV的`volumeHandle`参数中引用该AP.

# 密钥管理
Kubernetes secrets用于存储敏感信息，例如用户证书，密码或API密钥。 它们作为base64编码的字符串保存在etcd中。 在EKS上，etcd节点的EBS卷带有[EBS加密](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html)。 Pod可以通过引用`podSpec`中的密钥来检索Kubernetes秘密对象。 这些密钥可以映射到环境变量或作为卷安装。 有关创建机密的其他信息，请参见 https://kubernetes.io/docs/concepts/configuration/secret/ 。 

!!! 警告
    特定namespace中的密钥可由密钥namespace中的所有pod引用。

!!! 警告 
    节点授权者允许Kubelet读取安装到该节点的所有密钥. 

## 推荐建议
### 使用AWS KMS对Kubernetes机密进行信封加密
这使您可以使用唯一的数据加密密钥（DEK）来加密您的机密。 然后使用来自AWS KMS的密钥加密密钥（KEK）来加密DEK，该密钥可以按定期计划自动轮换。 使用Kubernetes的KMS插件，所有Kubernetes秘密都以密文而不是纯文本的形式存储在etcd中，并且只能由Kubernetes API服务器解密。
有关更多详细信息，请参阅[使用EKS加密提供程序支持进行深入防御](https://aws.amazon.com/blogs/containers/using-eks-encryption-provider-support-for-defense-in-depth/)

### 审核密钥的使用
在EKS上，打开审核日志记录并创建CloudWatch指标过滤器，并在使用机密时发出警报以提醒您（可选）。 以下是Kubernetes审核日志`{($.verb="get") && ($.objectRef.resource="secret")}`的指标过滤器的示例。 您还可以对CloudWatch Log Insights使用以下查询: 
```
fields @timestamp, @message
| sort @timestamp desc
| limit 100
| stats count(*) by objectRef.name as secret
| filter verb="get" and objectRef.resource="secrets"
```
上面的查询将显示在特定时间范围内访问密钥的次数. 
```
fields @timestamp, @message
| sort @timestamp desc
| limit 100
| filter verb="get" and objectRef.resource="secrets"
| display objectRef.namespace, objectRef.name, user.username, responseStatus.code
```
该查询将显示秘密以及尝试访问该密钥的用户的名称空间和用户名以及响应代码. 

### 定期轮换您的密钥
Kubernetes不会自动轮换秘密。 如果您必须轮换机密，请考虑使用外部机密存储，例如 Vault或AWS Secrets Manager. 

### 使用单独的名称空间作为隔离不同应用程序机密的方法
如果您拥有无法在名称空间中的应用程序之间共享的机密，请为这些应用程序创建一个单独的名称空间.

### 使用卷挂载代替环境变量
环境变量的值可能会意外地出现在日志中。 作为卷装载的密钥将实例化为tmpfs卷（RAM支持的文件系统），当删除pod时，这些卷会自动从节点中删除. 

### 使用外部密钥提供者
有几种可行的使用Kubernetes 密钥的替代方法，包括Bitnami的[Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets)和Hashicorp的[Vault](
https://www.hashicorp.com/blog/injecting-vault-secrets-into-kubernetes-pods-via-a-sidecar/)。 与可以在命名空间内的所有Pod之间共享的Kubernetes机密不同，Vault使您能够通过使用Kubernetes服务帐户来限制对特定Pod的访问。 它还支持秘密轮换。 如果您不喜欢Vault，则可以用AWS Secrets Manager使用类似的方法，例如本例 https://github.com/jicowan/secret-sidecar ，或者您可以尝试使用[serverless](https://github.com/mhausenblas/nase)变异webhook来代替。
