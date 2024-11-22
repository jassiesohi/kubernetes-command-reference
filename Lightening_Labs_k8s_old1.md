Lightening Lab

1. Cluster Upgrade

apt update
apt-cache madison kubeadm
kubectl get po -o wide
kubectl drain controlplane --ignore-daemonsets

controlplane ~ ➜  kubectl cordon controlplane
node/controlplane already cordoned

apt-mark unhold kubeadm && \
apt-get update && apt-get install -y kubeadm='1.27.0-00' && \
apt-mark hold kubeadm

kubeadm version
kubeadm upgrade plan

sudo kubeadm upgrade apply v1.27.0

apt-mark unhold kubelet kubectl && \
apt-get update && apt-get install -y kubelet='1.27.0-00' kubectl='1.27.0-00' && \
apt-mark hold kubelet kubectl

sudo systemctl daemon-reload
sudo systemctl restart kubelet

kubectl uncordon controlplane

kubectl get nodes

apt-mark unhold kubeadm && \
apt-get update && apt-get install -y kubeadm='1.27.0-00' && \
apt-mark hold kubeadm

on controlplane
kubectl drain node01 --ignore-daemonsets

node-role.kubernetes.io/control-plane:NoSchedule


node-role.kubernetes.io/control-plane:NoSchedule


tolerations:
     - key: "node-role.kubernetes.io/control-plane"
       effect: "NoSchedule"
       operator: "Exists"

apt update
apt-mark unhold kubeadm && \
apt-get update && apt-get install -y kubeadm='1.27.0-00' && \
apt-mark hold kubeadm
sudo kubeadm upgrade node

From Control plane
kubectl drain node01 --ignore-daemonsets

apt-mark unhold kubelet kubectl && \
apt-get update && apt-get install -y kubelet='1.27.0-00' kubectl='1.27.0-00' && \
apt-mark hold kubelet kubectl
sudo systemctl daemon-reload
sudo systemctl restart kubelet

kubectl create deploy nginx-deploy --image=nginx:1.16
kubectl set image deployment/nginx-deploy nginx=nginx:1.17

kubectl config set-context --current --namespace=alpha-mysql
kubectl config set-context --current --namespace=gamma



kubectl -n admin2406 get deployment -o custom-columns=DEPLOYMENT:.metadata.name,CONTAINER_IMAGE:.spec.template.spec.containers[].image,READY_REPLICAS:.status.readyReplicas,NAMESPACE:.metadata.namespace --sort-by=.metadata.name > /opt/admin2406_data



---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: mysql-alpha-pvc
  namespace: alpha
spec:
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
  storageClassName: slow
  
export ETCDCTL_API=3
etcdctl snapshot save --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/etcd/server.crt --key=/etc/kubernetes/pki/etcd/server.key --endpoints=127.0.0.1:2379 /opt/etcd-backup.db



Use the command kubectl run to create a pod definition file. Add secret volume and update container name in it.

Alternatively, run the following command:

kubectl run secret-1401 -n admin1401 --image=busybox --dry-run=client -oyaml --command -- sleep 4800 > admin.yaml

Add the secret volume and mount path to create a pod called secret-1401 in the admin1401 namespace as follows:


  
---
apiVersion: v1
kind: Pod
metadata:
  creationTimestamp: null
  labels:
    run: secret-1401
  name: secret-1401
  namespace: admin1401
spec:
  volumes:
  - name: secret-volume
    # secret volume
    secret:
      secretName: dotfile-secret
  containers:
  - command:
    - sleep
    - "4800"
    image: busybox
    name: secret-admin
    # volumes' mount path
    volumeMounts:
    - name: secret-volume
      readOnly: true
      mountPath: "/etc/secret-volume"
      

Delete the resources without waiting --grace-period=0 --force
