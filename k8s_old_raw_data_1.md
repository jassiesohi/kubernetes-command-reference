Multipass

Creating a user account using useradd command on Ubuntu
$ sudo useradd -s /bin/bash -d /home/vivek/ -m -G sudo vivek
$ sudo passwd vivek

Where,

-s /bin/bash – Set /bin/bash as login shell of the new account
-d /home/vivek/ – Set /home/vivek/ as home directory of the new Ubuntu account
-m – Create the user’s home directory
-G sudo – Make sure vivek user can sudo i.e. give admin access to the new account

cd .ssh/
vi authorized_keys
Copy Public Key of 13infotech

#Winscp id_rsa to .ssh/
chmod 600 id_rsa

-rw------- 1 13infotech 13infotech 1675 Feb 15 16:01 id_rsa

Command 'ifconfig' not found, but can be installed with:


$ sudo useradd -s /bin/bash -d /home/udplibrary/ -m -G sudo udplibrary
$ sudo passwd udplibrary

$ mkdir .ssh/
$ vi authorized_keys


C:\Windows\system32>multipass list
C:\Windows\system32>multipass delete aligator3
C:\Windows\system32>multipass delete aligator4
C:\Windows\system32>multipass purge
C:\Windows\system32>multipass shell aligator5




kubectl drain node01 --ignore-daemonsets
kubectl uncordon node01
kubectl describe no controlplane
kubectl describe node | grep Taints

kubectl get no -o wide 
kubectl get po -o wide

kubeadm upgrade plan
kubectl drain controlplane --ignore-daemonsets
apt update
apt install kubeadm=1.27.0-00
kubeadm upgrade apply v1.27.0
apt install kubelet=1.27.0-00
systemctl daemon-reload
systemctl restart kubelet
kubectl get no -o wide
kubectl drain node01 --ignore-daemonsets
apt update
apt install kubeadm=1.27.0-00
kubeadm upgrade node
apt install kubelet=1.27.0-00
systemctl daemon-reload
systemctl restart kubelet
kubectl uncordon node01

kubectl get deploy
kubectl describe po etcd-controlplane -n=kube-system
Image:         registry.k8s.io/etcd:3.5.7-0


ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/etcd/server.crt --key=/etc/kubernetes/pki/etcd/server.key \
  snapshot save /opt/snapshot-pre-boot.db

ETCDCTL_API=3 etcdctl --data-dir /var/lib/etcd-from-backup snapshot restore /opt/snapshot-pre-boot.db

kubectl config use-context cluster1
kubectl config use-context cluster2



ps -ef | grep -i etcd

etcdctl member list #it will not work

ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 --cacert=/etc/etcd/pki/ca.pem --cert=/etc/etcd/pki/etcd.pem --key=/etc/etcd/pki/etcd-key.pem member list

ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/etcd/server.crt --key=/etc/kubernetes/pki/etcd/server.key \
  snapshot save /opt/cluster1.db


scp cluster1-controlplane:/opt/cluster1.db /opt

scp /opt/cluster2.db etcd-server:/root


ETCDCTL_API=3 etcdctl snapshot restore /root/cluster2.db --data-dir=/var/lib/etcd-data-new
cd /var/lib
chown -R etcd.etcd etcd-data-new/

vi /etc/systemd/system/etcd.service
systemctl daemon-reload
systemctl restart etcd

kubectl config use-context cluster2

kubectl delete po kube-controller-manager-cluster2-controlplane  kube-scheduler-cluster2-controlplane -n=kube-system

cd /etc/kubernetes/manifests/


- kube-apiserver
    - --advertise-address=192.4.179.9
    - --allow-privileged=true
    - --authorization-mode=Node,RBAC
    - --client-ca-file=/etc/kubernetes/pki/ca.crt
    - --enable-admission-plugins=NodeRestriction
    - --enable-bootstrap-token-auth=true
    - --etcd-cafile=/etc/kubernetes/pki/etcd/ca.crt
    - --etcd-certfile=/etc/kubernetes/pki/apiserver-etcd-client.crt
    - --etcd-keyfile=/etc/kubernetes/pki/apiserver-etcd-client.key
    - --etcd-servers=https://127.0.0.1:2379
    - --kubelet-client-certificate=/etc/kubernetes/pki/apiserver-kubelet-client.crt
    - --kubelet-client-key=/etc/kubernetes/pki/apiserver-kubelet-client.key
    - --kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname
    - --proxy-client-cert-file=/etc/kubernetes/pki/front-proxy-client.crt
    - --proxy-client-key-file=/etc/kubernetes/pki/front-proxy-client.key
    - --requestheader-allowed-names=front-proxy-client
    - --requestheader-client-ca-file=/etc/kubernetes/pki/front-proxy-ca.crt
    - --requestheader-extra-headers-prefix=X-Remote-Extra-
    - --requestheader-group-headers=X-Remote-Group
    - --requestheader-username-headers=X-Remote-User
    - --secure-port=6443
    - --service-account-issuer=https://kubernetes.default.svc.cluster.local
    - --service-account-key-file=/etc/kubernetes/pki/sa.pub
    - --service-account-signing-key-file=/etc/kubernetes/pki/sa.key
    - --service-cluster-ip-range=10.96.0.0/12
    - --tls-cert-file=/etc/kubernetes/pki/apiserver.crt
    - --tls-private-key-file=/etc/kubernetes/pki/apiserver.key



/etc/kubernetes/pki/apiserver.crt
openssl x509 -in /etc/kubernetes/pki/apiserver.crt -text


--cert-file=/etc/kubernetes/pki/etcd/server.crt
openssl x509 -in /etc/kubernetes/pki/etcd/server.crt -text


--tls-cert-file=/etc/kubernetes/pki/apiserver.crt

/etc/kubernetes/pki/ca.crt
openssl x509 -in /etc/kubernetes/pki/car.crt


crictl ps -a | grep kube-apiserver
crictl logs 7a86b0a97da8b (container-id)


crictl ps -a | grep etcd

crictl logs ea8f369f64117


cat akshay.csr | base64 -w 0

apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: akshay
spec:
  request: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ1ZqQ0NBVDRDQVFBd0VURVBNQTBHQTFVRUF3d0dZVzVuWld4aE1JSUJJakFOQmdrcWhraUc5dzBCQVFFRgpBQU9DQVE4QU1JSUJDZ0tDQVFFQTByczhJTHRHdTYxakx2dHhWTTJSVlRWMDNHWlJTWWw0dWluVWo4RElaWjBOCnR2MUZtRVFSd3VoaUZsOFEzcWl0Qm0wMUFSMkNJVXBGd2ZzSjZ4MXF3ckJzVkhZbGlBNVhwRVpZM3ExcGswSDQKM3Z3aGJlK1o2MVNrVHF5SVBYUUwrTWM5T1Nsbm0xb0R2N0NtSkZNMUlMRVI3QTVGZnZKOEdFRjJ6dHBoaUlFMwpub1dtdHNZb3JuT2wzc2lHQ2ZGZzR4Zmd4eW8ybmlneFNVekl1bXNnVm9PM2ttT0x1RVF6cXpkakJ3TFJXbWlECklmMXBMWnoyalVnald4UkhCM1gyWnVVV1d1T09PZnpXM01LaE8ybHEvZi9DdS8wYk83c0x0MCt3U2ZMSU91TFcKcW90blZtRmxMMytqTy82WDNDKzBERHk5aUtwbXJjVDBnWGZLemE1dHJRSURBUUFCb0FBd0RRWUpLb1pJaHZjTgpBUUVMQlFBRGdnRUJBR05WdmVIOGR4ZzNvK21VeVRkbmFjVmQ1N24zSkExdnZEU1JWREkyQTZ1eXN3ZFp1L1BVCkkwZXpZWFV0RVNnSk1IRmQycVVNMjNuNVJsSXJ3R0xuUXFISUh5VStWWHhsdnZsRnpNOVpEWllSTmU3QlJvYXgKQVlEdUI5STZXT3FYbkFvczFqRmxNUG5NbFpqdU5kSGxpT1BjTU1oNndLaTZzZFhpVStHYTJ2RUVLY01jSVUyRgpvU2djUWdMYTk0aEpacGk3ZnNMdm1OQUxoT045UHdNMGM1dVJVejV4T0dGMUtCbWRSeEgvbUNOS2JKYjFRQm1HCkkwYitEUEdaTktXTU0xMzhIQXdoV0tkNjVoVHdYOWl4V3ZHMkh4TG1WQzg0L1BHT0tWQW9FNkpsYWFHdTlQVmkKdjlOSjVaZlZrcXdCd0hKbzZXdk9xVlA3SVFjZmg3d0drWm89Ci0tLS0tRU5EIENFUlRJRklDQVRFIFJFUVVFU1QtLS0tLQo=
  signerName: kubernetes.io/kube-apiserver-client
  usages:
  - client auth
  
  
  kubectl get csr
  kubectl certificate approve akshay
  
  kubectl get csr agent-smith -o yaml
  kubectl certificate deny agent-smith
  kubectl delete csr agent-smith
  
  
  kubectl describe po kube-apiserver-controlplane -n=kube-system
  --authorization-mode=Node,RBAC
  
  or 
  ps -aux | grep authorization
  
  
  kubectl get roles -A --no-headers | wc -l
  
  kubectl describe role kube-proxy -n=kube-system
  kubectl describe rolebinding kube-proxy -n=kube-system
  kubectl get po --as dev-user
  
  
  kubectl create role developer --namespace=default --verb=list,create,delete --resource=pods
  kubectl create rolebinding dev-user-binding --namespace=default --role=developer --user=dev-user
  
  
  apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  creationTimestamp: "2023-11-07T04:40:19Z"
  name: developer
  namespace: blue
  resourceVersion: "3809"
  uid: 027c3773-440e-4d5d-bbaa-8b5d35e571ee
rules:
- apiGroups:
  - ""
  resourceNames:
  - dark-blue-app
  resources:
  - pods
  verbs:
  - get
  - watch
  - create
  - delete
- apiGroups:
  - apps
  resources:
  - deployments
  verbs:
  - get
  - watch
  - create
  - delete
  
  
  kubectl describe role developer -n=blue
  kubectl --as dev-user create deploy nginx --image=nginx -n=blue
  
  
kubectl get clusterroles --no-headers | wc -l
kubectl get clusterrolebindings --no-headers | wc -l
kubectl api-resources --namespaced=false
kubectl describe clusterrolebinding cluster-admin
kubectl create clusterrolemichelle-role --verb=get,list,watch --resource=nodes
kubectl create clusterrolebinding michelle-binding --clusterrole=michelle-role --user=michelle
kubectl describe clusterrole michelle role
kubectl describe clusterrolebinding michelle-binding
kubectl get nodes --as michelle

kubectl describe clusterrole cluster-admin
kubectl auth can-i list nodes --as michelle

kubectl api-resources

kubectl create clusterrole storage-admin --resource=persistentvolumes,storageclasses --verb=list,create,get,watch 
kubectl describe clusterrole storage-admin
kubectl create clusterrolebinding michelle-storage-admin --user=michelle --clusterrole=storage-admin

  
ip address show type bridge
netstat -npl | grep -i scheduler

netstat -npl | grep -i scheduler
tcp        0      0 127.0.0.1:10259         0.0.0.0:*               LISTEN      3515/kube-scheduler 


ps -aux | grep -i kubelet | grep container-runtime

cd /opt/cni/bin
ls /etc/cni/net.d/10-flannel.conflist

kubectl get po -o wide -n=kube-system | grep weave
ip addr show weave


kubectl exec busybox -- ip route

ubectl get svc -n=kube-system
NAME       TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)                  AGE
kube-dns   ClusterIP   10.96.0.10   <none>        53/UDP,53/TCP,9153/TCP   4m13s

kubectl describe deploy coredns -n=kube-system
Args:
      -conf
      /etc/coredns/Corefile
      

kubectl exec -it hr -- nslookup mysql.payroll > /root/CKA/nslookup.out

kubectl get ingress --all-namespaces
kubectl describe ingress -n=app-space
kubectl get deploy --all-namespaces


kubectl create ingress ingress-pay -n=critical-space --rule="/pay=pay-service:8282" 

curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-archive-keyring.gpg



echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.27/deb/ /' | sudo tee /etc/apt/sources.list.d/kubernetes.list

echo "deb [signed-by=/etc/apt/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee /etc/apt/sources.list.d/kubernetes.list


sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl

mkdir -p /etc/apt/keyrings

curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-archive-keyring.gpg

echo "deb [signed-by=/etc/apt/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee /etc/apt/sources.list.d/kubernetes.list

sudo apt-get update

sudo apt-get install -y kubelet=1.27.0-00 kubeadm=1.27.0-00 kubectl=1.27.0-00

sudo apt-mark hold kubelet kubeadm kubectl

kubelet --version

sudo kubeadm init --apiserver-cert-extra-sans=controlplane --apiserver-advertise-address=192.6.136.10 --pod-network-cidr=10.244.0.0/16



On the controlplane node, run the following set of commands to deploy the network plugin:
Download the original YAML file and save it as kube-flannel.yml:
curl -LO https://raw.githubusercontent.com/flannel-io/flannel/v0.20.2/Documentation/kube-flannel.yml
Open the kube-flannel.yml file using a text editor.

Locate the args section within the kube-flannel container definition. It should look like this:

  args:
  - --ip-masq
  - --kube-subnet-mgr
Add the additional argument - --iface=eth0 to the existing list of arguments.

Now apply the modified manifest kube-flannel.yml file using kubectl:

kubectl apply -f kube-flannel.yml
After applying the manifest, the STATUS of both the nodes should become Ready

controlplane ~ ➜  kubectl get nodes
NAME           STATUS   ROLES           AGE   VERSION
controlplane   Ready    control-plane   15m   v1.27.0
node01         Ready    <none>          15m   v1.27.0



kubectl config set-context --current --namespace=gamma

kubectl scale deploy app --replicas=2

kubectl logs kube-controller-manager-controlplane -n=kube-system


Inspect the logs using journalctl -u kubelet -f

vi /var/lib/kubelet/config.yaml

kubectl logs kube-proxy-l5dkw -n=kube-system


kubectl describe cm kube-proxy -n=kube-system
/var/lib/kube-proxy/kubeconfig.conf



kubectl get nodes -o json > /opt/outputs/nodes.json
kubectl get no node01 -o json > /opt/outputs/node01.json
kubectl get nodes -o=jsonpath='{.items[*].metadata.name}' > /opt/outputs/node_names.txt
kubectl get no -o=jsonpath='{.items[*].status.nodeInfo.osImage}' > /opt/outputs/nodes_os.txt

kubectl config view --kubeconfig=/root/my-kube-config
kubectl config view --kubeconfig=/root/my-kube-config -o=jsonpath='{.users[*].name}' > /opt/outputs/users.txt
kubectl get pv --sort-by=.spec.capacity.storage > /opt/outputs/storage-capacity-sorted.txt
kubectl get pv --sort-by=.spec.capacity.storage -o=custom-columns=NAME:.metadata.name,CAPACITY:.spec.capacity.storage > /opt/outputs/pv-and-capacity-sorted.txt
kubectl config view --kubeconfig=my-kube-config -o jsonpath="{.contexts[?(@.context.user=='aws-user')].name}" > /opt/outputs/aws-context-name

Lightening Lab

1. 
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