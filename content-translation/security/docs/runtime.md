# Runtime 安全 
运行时安全性为容器在运行时提供了积极的保护。 这个想法是要检测和/或防止在容器内部发生恶意活动。 使用安全计算（seccomp），可以防止容器化的应用程序对基础主机操作系统的内核进行某些syscall。 虽然Linux操作系统有数百个系统调用，但是运行容器并不需要它们的大部分。 通过限制容器可以进行的系统调用，可以有效地减少应用程序的攻击面。 要开始使用seccomp，请分析堆栈跟踪的结果以查看您的应用程序正在执行哪个调用，或使用诸如[syscall2seccomp](https://github.com/antitree/syscall2seccomp)之类的工具.

与SELinux不同，seccomp并非旨在将容器彼此隔离，但是，它将保护主机内核免遭未经授权的系统调用。 它通过拦截系统调用并仅允许已列入白名单的系统调用来工作。 Docker有一个[default](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) seccomp配置文件，适用于大多数通用工作负载。 您还可以为需要其他特权的内容创建自己的配置文件.

!!! 警告
    seccomp配置文件是Kubelet alpha功能。 您需要在Kubelet参数中添加`--seccomp-profile-root`标志才能使用此功能. 

AppArmor与seccomp相似，只是它限制了容器的功能，包括访问文件系统的各个部分。 它可以强制执行或投诉模式运行。 由于构建Apparmor配置文件可能具有挑战性，因此建议您改用[bane](https://github.com/genuinetools/bane)之类的工具. 

!!! 注意
    Apparmor仅适用于Linux的Ubuntu / Debian发行版. 

!!! 注意 
    Kubernetes当前不提供任何将AppArmor或seccomp配置文件加载到节点上的本机机制。 它们必须手动加载或在引导时安装到节点上。 这必须在Pod中引用它们之前完成，因为调度程序无法知道哪些节点具有配置文件. 

## 推荐建议
### 使用第三方解决方案进行运行时防御
如果您不熟悉Linux安全性，则很难创建和管理seccomp和Apparmor配置文件。 如果您没有时间精通，请考虑使用商业解决方案。 他们中的许多人已经超越了诸如Apparmor和seccomp之类的静态配置文件，并开始使用机器学习来阻止或警告可疑活动。 可以在下面的[工具](##工具) 部分中找到其中一些解决方案。 可以在[AWS容器市场](https://aws.amazon.com/marketplace/features/containers) 中找到其他选项。

### 在编写seccomp策略之前考虑添加/删除Linux Capability
Capability涉及对系统调用可访问的内核功能的各种检查。 如果检查失败，则系统调用通常会返回错误。 可以在特定系统调用开始时进行检查，也可以在内核中更深的区域进行检查，这些区域可以通过多个不同的系统调用来访问（例如，写入特定的特权文件）。 另一方面，Seccomp是一个系统调用筛选器，该筛选器将在所有系统调用运行之前应用到它们。 进程可以设置一个筛选器，使他们可以撤消运行某些系统调用或某些系统调用的特定参数的权利. 

在使用seccomp之前，请考虑添加/删除Linux capabilities是否可以为您提供所需的控制。 有关更多信息，请参见 https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container . 

### 查看您是否可以通过使用Pod安全策略（PSP）实现目标
Pod安全策略提供了许多种不同的方法来改善您的安全状况，而又不会引起不必要的复杂性。 在尝试构建seccomp和Apparmor配置文件之前，请先探索PSP中可用的选项。. 

!!! 警告 
    由于PSP的未来前景不确定，您可能希望使用Pod安全上下文或OPA / Gatekeeper来实现这些控件。 可以从[Gatekeeper](https://github.com/open-policy-agent/gatekeeper/tree/master/library/pod-security-policy)在在GitHub的存储库中拉取 一组Gatekeeper用于实施PSP中常见的策略约束和约束模板的集合。

## 其他资源
+ [开始之前应该知道的7件事](https://itnext.io/seccomp-in-kubernetes-part-i-7-things-you-should-know-before-you-even-start-97502ad6b6d6)
+ [AppArmor Loader](https://github.com/kubernetes/kubernetes/tree/master/test/images/apparmor-loader)
+ [使用配置文件设置节点](https://kubernetes.io/docs/tutorials/clusters/apparmor/#setting-up-nodes-with-profiles)

## 工具
+ [Aqua](https://www.aquasec.com/products/aqua-cloud-native-security-platform/)
+ [Qualys](https://www.qualys.com/apps/container-security/)
+ [Stackrox](https://www.stackrox.com/use-cases/threat-detection/)
+ [Sysdig Secure](https://sysdig.com/products/kubernetes-security/)
+ [Twistlock](https://www.twistlock.com/platform/runtime-defense/)
