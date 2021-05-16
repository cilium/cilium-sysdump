module github.com/cilium/cilium-sysdump

go 1.16

require (
	github.com/cilium/cilium v1.8.10
	github.com/hashicorp/go-multierror v1.0.0
	github.com/mholt/archiver/v3 v3.5.0
	github.com/sirupsen/logrus v1.8.1
	k8s.io/api v0.18.18
	k8s.io/apimachinery v0.18.18
	k8s.io/cli-runtime v0.18.17
	k8s.io/client-go v0.18.18
	k8s.io/klog v1.0.0
)

replace (
	github.com/optiopay/kafka => github.com/cilium/kafka v0.0.0-20180809090225-01ce283b732b
	k8s.io/client-go => github.com/cilium/client-go v0.0.0-20210417023617-aeb4c6f1b557
)
