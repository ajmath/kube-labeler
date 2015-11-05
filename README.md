# kube-labeler

Simple docker image for applying kubernetes labels to nodes from fleet or EC2.

This is intended to be run on the node that needs labeling.  In order for the
script to identify which node it is in the cluster, it makes an assumption that
a host IP will match either the `metadata.name`, `spec.externalID`, or one of
`node.addresses[].address`.

Usage:
```
docker run --rm --name kube-labeler ajmath/kube-labeler --kube-master http://kube:8080 --fleet-socket
