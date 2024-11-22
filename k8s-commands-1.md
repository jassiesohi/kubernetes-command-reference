

Q. 11
info_outline
Question
Use JSON PATH query to retrieve the osImages of all the nodes and store it in a file /opt/outputs/nodes_os_x43kj56.txt.

The osImages are under the nodeInfo section under status of each node.

info_outline
Solution
Run the command: kubectl get nodes -o jsonpath='{.items[*].status.nodeInfo.osImage}' > /opt/outputs/nodes_os_x43kj56.txt




kubectl run nginx --image=nginx; kubectl get po -o wide
curl http://10.10.0.4

nerdctl -n=k8s.io ps -a


kubenetes POD DNS Format

<podname>.<namespace>.pod.cluster.local
10-10-0-50.default.pod.cluster.local

kubectl run curl --image=curlimages/curl --restart=Never -- sh -c "sleep infinity"
kubectl exec -it curl -- sh -c "curl example.com"
kubectl exec -it curl -- sh -c "nslookup example.com"

kcurl() { kubectl exec -it curl -- sh -c "curl $1"; }
knslookup() { kubectl exec -it curl -- sh -c "nslookup $1"; }

kcurl example.com
knslookup example.com

kcurl nginx.default.svc.cluster.local
knslookup 10-10-0-50.default.pod.cluster.local


kubectl describe no controlplane | vi -

vim .vimrc
set ts=2 sts=2 sw=2 et nu ai cuc cul

cat /etc/kubernetes/manifests/etcd.yaml | grep file

kubectl get no -o json | jq -c 'paths'
kubectl get no -o json | jq -c 'paths'| grep type | grep -v condition

kubectl get no -o jsonpath='{.items[0].status.address}' | jq




echo 'VGhpcyBpcyB0aGUgc2VjcmV0IQo=' | base64 --decode


always use vim instead of vi
:set autoindent


alias check="k get deploy,svc,rs,ds,po,secrets,pv,pvc,netpol"

drun="--dry-run=client -oyaml"
alias replace="k --grace-period=0 replace --force -f"
alias apply="k apply -f"

journalctl -xe
ps -aux | grep kubelet


15-pending
curl cyan-svc-cka28-trb.cyan-ns-cka28-trb.svc.cluster.local


k get po -A --sort-by=.metadata.creationTimestamps
k get po -A --sort-by=.metadata.creationTimestamps | tac
echo "k get po -A --sort-by=.metadata.creationTimestamps | tac" > /opt/pods_asc.sh
chmod +x /opt/pods_asc.sh




info_outline
Question
SECTION: ARCHITECTURE, INSTALL AND MAINTENANCE


For this question, please set the context to cluster1 by running:


kubectl config use-context cluster1


We have created a service account called red-sa-cka23-arch, a cluster role called red-role-cka23-arch and a cluster role binding called red-role-binding-cka23-arch.


Identify the permissions of this service account and write down the answer in file /opt/red-sa-cka23-arch in format resource:pods|verbs:get,list on student-node


info_outline
Solution
Get the red-role-cka23-arch role permissions:


student-node ~ ➜  kubectl get clusterrole red-role-cka23-arch -o json --context cluster1

{
    "apiVersion": "rbac.authorization.k8s.io/v1",
    "kind": "ClusterRole",
    "metadata": {
        "creationTimestamp": "2022-10-20T07:16:39Z",
        "name": "red-role-cka23-arch",
        "resourceVersion": "16324",
        "uid": "e53cef4f-ae1b-49f7-b9fa-ac5e7e22a61c"
    },
    "rules": [
        {
            "apiGroups": [
                "apps"
            ],
            "resources": [
                "deployments"
            ],
            "verbs": [
                "get",
                "list",
                "watch"
            ]
        }
    ]
}

In this case, add data in file as below:

student-node ~ ➜ echo "resource:deployments|verbs:get,list,watch" > /opt/red-sa-cka23-arch

info_outline
Question
SECTION: TROUBLESHOOTING


For this question, please set the context to cluster4 by running:


kubectl config use-context cluster4


There is a pod called pink-pod-cka16-trb created in the default namespace in cluster4. This app runs on port tcp/5000 and it is exposed to end-users using an ingress resource called pink-ing-cka16-trb in such a way that it is supposed to be accessible using the command: curl http://kodekloud-pink.app on cluster4-controlplane host.


However, this is not working. Troubleshoot and fix this issue, making any necessary to the objects.



Note: You should be able to ssh into the cluster4-controlplane using ssh cluster4-controlplane command.

info_outline
Solution
SSH into the cluster4-controlplane host and try to access the app.
ssh cluster4-controlplane
curl kodekloud-pink.app


You must be getting 503 Service Temporarily Unavailabl error.
Let's look into the service:

kubectl edit svc pink-svc-cka16-trb
Under ports: change protocol: UDP to protocol: TCP



Try to access the app again

curl kodekloud-pink.app
You must be getting curl: (6) Could not resolve host: example.com error, from the error we can see that its not able to resolve example.com host which indicated that it can be some issue related to the DNS. As we know CoreDNS is a DNS server that can serve as the Kubernetes cluster DNS, so it can be something related to CoreDNS.

Let's check if we have CoreDNS deployment running:


kubectl get deploy -n kube-system
You will see that for coredns all relicas are down, you will see 0/0 ready pods. So let's scale up this deployment.

kubectl scale --replicas=2 deployment coredns -n kube-system

Once CoreDBS is up let's try to access to app again.

curl kodekloud-pink.app
It should work now.


ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/etcd/server.crt --key=/etc/kubernetes/pki/etcd/server.key \
  snapshot save /opt/etcd-boot-cka18-trb.db
  
  
Question
SECTION: TROUBLESHOOTING


For this question, please set the context to cluster1 by running:


kubectl config use-context cluster1

It appears that the black-cka25-trb deployment in cluster1 isn't up to date. While listing the deployments, we are currently seeing 0 under the UP-TO-DATE section for this deployment. Troubleshoot, fix and make sure that this deployment is up to date.

info_outline
Solution
Check current status of the deployment

kubectl get deploy 
Let's check deployment status

kubectl get deploy black-cka25-trb -o yaml
Under status: you will see message: Deployment is paused so seems like deployment was paused, let check the rollout status


kubectl rollout status deployment black-cka25-trb

You will see this message
Waiting for deployment "black-cka25-trb" rollout to finish: 0 out of 1 new replicas have been updated...

So, let's resume

kubectl rollout resume deployment black-cka25-trb

Check again the status of the deployment

kubectl get deploy 
It should be good now.


Question
SECTION: STORAGE


For this question, please set the context to cluster1 by running:


kubectl config use-context cluster1


We want to deploy a python based application on the cluster using a template located at /root/olive-app-cka10-str.yaml on student-node. However, before you proceed we need to make some modifications to the YAML file as per details given below:


The YAML should also contain a persistent volume claim with name olive-pvc-cka10-str to claim a 100Mi of storage from olive-pv-cka10-str PV.


Update the deployment to add a sidecar container, which can use busybox image (you might need to add a sleep command for this container to keep it running.)

Share the python-data volume with this container and mount the same at path /usr/src. Make sure this container only has read permissions on this volume.


Finally, create a pod using this YAML and make sure the POD is in Running state.


Update olive-app-cka10-str.yaml template so that it looks like as below:

---
kind: PersistentVolumeClaim
apiVersion: v1
metadata:
  name: olive-pvc-cka10-str
spec:
  accessModes:
  - ReadWriteMany
  storageClassName: olive-stc-cka10-str
  volumeName: olive-pv-cka10-str
  resources:
    requests:
      storage: 100Mi

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: olive-app-cka10-str
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: olive-app-cka10-str
    spec:
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
            - matchExpressions:
              - key: kubernetes.io/hostname
                operator: In
                values:
                  - cluster1-node01
      containers:
      - name: python
        image: poroko/flask-demo-app
        ports:
        - containerPort: 5000
        volumeMounts:
        - name: python-data
          mountPath: /usr/share/
      - name: busybox
        image: busybox
        command:
          - "bin/sh"
          - "-c"
          - "sleep 10000"
        volumeMounts:
          - name: python-data
            mountPath: "/usr/src"
            readOnly: true
      volumes:
      - name: python-data
        persistentVolumeClaim:
          claimName: olive-pvc-cka10-str
  selector:
    matchLabels:
      app: olive-app-cka10-str

---
apiVersion: v1
kind: Service
metadata:
  name: olive-svc-cka10-str
spec:
  type: NodePort
  ports:
    - port: 5000
      nodePort: 32006
  selector:
    app: olive-app-cka10-str
Apply the template:

kubectl apply -f olive-app-cka10-str.yaml



info_outline
Question
SECTION: SERVICE NETWORKING


For this question, please set the context to cluster3 by running:


kubectl config use-context cluster3


Part I:



Create a ClusterIP service .i.e. service-3421-svcn in the spectra-1267 ns which should expose the pods namely pod-23 and pod-21 with port set to 8080 and targetport to 80.



Part II:



Store the pod names and their ip addresses from the spectra-1267 ns at /root/pod_ips_cka05_svcn where the output is sorted by their IP's.

Please ensure the format as shown below:



POD_NAME        IP_ADDR
pod-1           ip-1
pod-3           ip-2
pod-2           ip-3
...


info_outline
Solution
Switching to cluster3:



kubectl config use-context cluster3



The easiest way to route traffic to a specific pod is by the use of labels and selectors . List the pods along with their labels:



student-node ~ ➜  kubectl get pods --show-labels -n spectra-1267
NAME     READY   STATUS    RESTARTS   AGE     LABELS
pod-12   1/1     Running   0          5m21s   env=dev,mode=standard,type=external
pod-34   1/1     Running   0          5m20s   env=dev,mode=standard,type=internal
pod-43   1/1     Running   0          5m20s   env=prod,mode=exam,type=internal
pod-23   1/1     Running   0          5m21s   env=dev,mode=exam,type=external
pod-32   1/1     Running   0          5m20s   env=prod,mode=standard,type=internal
pod-21   1/1     Running   0          5m20s   env=prod,mode=exam,type=external


Looks like there are a lot of pods created to confuse us. But we are only concerned with the labels of pod-23 and pod-21.



As we can see both the required pods have labels mode=exam,type=external in common. Let's confirm that using kubectl too:



student-node ~ ➜  kubectl get pod -l mode=exam,type=external -n spectra-1267                                    
NAME     READY   STATUS    RESTARTS   AGE
pod-23   1/1     Running   0          9m18s
pod-21   1/1     Running   0          9m17s


Nice!! Now as we have figured out the labels, we can proceed further with the creation of the service:



student-node ~ ➜  kubectl create service clusterip service-3421-svcn -n spectra-1267 --tcp=8080:80 --dry-run=client -o yaml > service-3421-svcn.yaml


Now modify the service definition with selectors as required before applying to k8s cluster:



student-node ~ ➜  cat service-3421-svcn.yaml 
apiVersion: v1
kind: Service
metadata:
  creationTimestamp: null
  labels:
    app: service-3421-svcn
  name: service-3421-svcn
  namespace: spectra-1267
spec:
  ports:
  - name: 8080-80
    port: 8080
    protocol: TCP
    targetPort: 80
  selector:
    app: service-3421-svcn  # delete 
    mode: exam    # add
    type: external  # add
  type: ClusterIP
status:
  loadBalancer: {}



Finally let's apply the service definition:


student-node ~ ➜  kubectl apply -f service-3421-svcn.yaml
service/service-3421 created

student-node ~ ➜  k get ep service-3421-svcn -n spectra-1267
NAME           ENDPOINTS                     AGE
service-3421   10.42.0.15:80,10.42.0.17:80   52s

To store all the pod name along with their IP's , we could use imperative command as shown below:



student-node ~ ➜  kubectl get pods -n spectra-1267 -o=custom-columns='POD_NAME:metadata.name,IP_ADDR:status.podIP' --sort-by=.status.podIP

POD_NAME   IP_ADDR
pod-12     10.42.0.18
pod-23     10.42.0.19
pod-34     10.42.0.20
pod-21     10.42.0.21
...

# store the output to /root/pod_ips
student-node ~ ➜  kubectl get pods -n spectra-1267 -o=custom-columns='POD_NAME:metadata.name,IP_ADDR:status.podIP' --sort-by=.status.podIP > /root/pod_ips_cka05_svcn

Question
SECTION: SERVICE NETWORKING


For this question, please set the context to cluster1 by running:


kubectl config use-context cluster1


John is setting up a two tier application stack that is supposed to be accessible using the service curlme-cka01-svcn. To test that the service is accessible, he is using a pod called curlpod-cka01-svcn. However, at the moment, he is unable to get any response from the application.



Troubleshoot and fix this issue so the application stack is accessible.



While you may delete and recreate the service curlme-cka01-svcn, please do not alter it in anyway.

info_outline
Solution
Test if the service curlme-cka01-svcn is accessible from pod curlpod-cka01-svcn or not.


kubectl exec curlpod-cka01-svcn -- curl curlme-cka01-svcn

.....
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:--  0:00:10 --:--:--     0


We did not get any response. Check if the service is properly configured or not.


kubectl describe svc curlme-cka01-svcn ''

....
Name:              curlme-cka01-svcn
Namespace:         default
Labels:            <none>
Annotations:       <none>
Selector:          run=curlme-ckaO1-svcn
Type:              ClusterIP
IP Family Policy:  SingleStack
IP Families:       IPv4
IP:                10.109.45.180
IPs:               10.109.45.180
Port:              <unset>  80/TCP
TargetPort:        80/TCP
Endpoints:         <none>
Session Affinity:  None
Events:            <none>


The service has no endpoints configured. As we can delete the resource, let's delete the service and create the service again.

To delete the service, use the command kubectl delete svc curlme-cka01-svcn.
You can create the service using imperative way or declarative way.


Using imperative command:
kubectl expose pod curlme-cka01-svcn --port=80

Using declarative manifest:


apiVersion: v1
kind: Service
metadata:
  labels:
    run: curlme-cka01-svcn
  name: curlme-cka01-svcn
spec:
  ports:
  - port: 80
    protocol: TCP
    targetPort: 80
  selector:
    run: curlme-cka01-svcn
  type: ClusterIP


You can test the connection from curlpod-cka-1-svcn using following.


kubectl exec curlpod-cka01-svcn -- curl curlme-cka01-svcn



---

cat john.csr 
-----BEGIN CERTIFICATE REQUEST-----
MIICVDCCATwCAQAwDzENMAsGA1UEAwwEam9objCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBALeHYZK0eHrOG4eUn+dei6qYAG8pWpETA/jolfyKy2KbX911
7CjYdB+fqX5JdB35oMibJ07mWSpE6FbRUNOyZWnKgMEzWtNZ/0bPVqDU51cp8YWT
DH+ZF9MRD5rvehYRUqOGuDOWoocz8XfjHmIy97pcxD3qR+6qlYFCHxwldpn9BneJ
777nIjVYvcgCbSW+hKmDgdUha0doyq/i4ps4Wg3ux6jkPTLHWarMUN1PhxzJSO4i
rDeGNCclfdcBPpbIh5Ea50UTeqohOJDQRriZSt+ogv4Vavp+2sIEgDWsgLCZFqP+
QyjxpVF7U+nWN06Ng29J8FMGSMrlvRquT/696h8CAwEAAaAAMA0GCSqGSIb3DQEB
CwUAA4IBAQBv6IlXZYHhCpO1TdZ+7cG56zkKjNnUTzyViUFqMbwh7wSqHvQhpfKh
HSveekCO1mYzAx41TmiNT/PZaHivAPuZUoqFYQkV+PlzemAs/S9j/16aE4WDGQli
ipVBpuSC5BTaCWpLHsOqxUeEU2QkewTj32pp4dVeXqTOFprW6OeruAV77VOkIo0W
XowfwONKESNv+Mi1nrG9AZIccve1tPfLVDsdmAFgnBatAmb1aUY4JRQLe1NrGDsQ
PrWLlgws5v57w7TDQvxg38Mjovkx/juy1DhOraKzGeKwVloQBJLo7xxc8wIfqRlY
AfQCsDvuoexAlNinNZcShy+Q3Ha00/Aq
-----END CERTIFICATE REQUEST-----

apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: myuser
spec:
  request: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ1ZqQ0NBVDRDQVFBd0VURVBNQTBHQTFVRUF3d0dZVzVuWld4aE1JSUJJakFOQmdrcWhraUc5dzBCQVFFRgpBQU9DQVE4QU1JSUJDZ0tDQVFFQTByczhJTHRHdTYxakx2dHhWTTJSVlRWMDNHWlJTWWw0dWluVWo4RElaWjBOCnR2MUZtRVFSd3VoaUZsOFEzcWl0Qm0wMUFSMkNJVXBGd2ZzSjZ4MXF3ckJzVkhZbGlBNVhwRVpZM3ExcGswSDQKM3Z3aGJlK1o2MVNrVHF5SVBYUUwrTWM5T1Nsbm0xb0R2N0NtSkZNMUlMRVI3QTVGZnZKOEdFRjJ6dHBoaUlFMwpub1dtdHNZb3JuT2wzc2lHQ2ZGZzR4Zmd4eW8ybmlneFNVekl1bXNnVm9PM2ttT0x1RVF6cXpkakJ3TFJXbWlECklmMXBMWnoyalVnald4UkhCM1gyWnVVV1d1T09PZnpXM01LaE8ybHEvZi9DdS8wYk83c0x0MCt3U2ZMSU91TFcKcW90blZtRmxMMytqTy82WDNDKzBERHk5aUtwbXJjVDBnWGZLemE1dHJRSURBUUFCb0FBd0RRWUpLb1pJaHZjTgpBUUVMQlFBRGdnRUJBR05WdmVIOGR4ZzNvK21VeVRkbmFjVmQ1N24zSkExdnZEU1JWREkyQTZ1eXN3ZFp1L1BVCkkwZXpZWFV0RVNnSk1IRmQycVVNMjNuNVJsSXJ3R0xuUXFISUh5VStWWHhsdnZsRnpNOVpEWllSTmU3QlJvYXgKQVlEdUI5STZXT3FYbkFvczFqRmxNUG5NbFpqdU5kSGxpT1BjTU1oNndLaTZzZFhpVStHYTJ2RUVLY01jSVUyRgpvU2djUWdMYTk0aEpacGk3ZnNMdm1OQUxoT045UHdNMGM1dVJVejV4T0dGMUtCbWRSeEgvbUNOS2JKYjFRQm1HCkkwYitEUEdaTktXTU0xMzhIQXdoV0tkNjVoVHdYOWl4V3ZHMkh4TG1WQzg0L1BHT0tWQW9FNkpsYWFHdTlQVmkKdjlOSjVaZlZrcXdCd0hKbzZXdk9xVlA3SVFjZmg3d0drWm89Ci0tLS0tRU5EIENFUlRJRklDQVRFIFJFUVVFU1QtLS0tLQo=
  signerName: kubernetes.io/kube-apiserver-client
  expirationSeconds: 86400  # one day
  usages:
  - client auth
  
  Create a nginx pod called nginx-resolver using image nginx, expose it internally with a service called nginx-resolver-service. Test that you are able to look up the service and pod names from within the cluster. Use the image: busybox:1.28 for dns lookup. Record results in /root/CKA/nginx.svc and /root/CKA/nginx.pod


Pod: nginx-resolver created

Service DNS Resolution recorded correctly

Pod DNS resolution recorded correctly

Create a static pod on node01 called nginx-critical with image nginx and make sure that it is recreated/restarted automatically in case of a failure.


Use /etc/kubernetes/manifests as the Static Pod path for example.

static pod configured under /etc/kubernetes/manifests ?

Pod nginx-critical-node01 is up and running


kubectl create sa pvviewer

kubectl create clusterrole pod-reader --verb=get,list,watch --resource=pods
kubectl create clusterrole pvviewer-role --verb=list --resource=persistentvolumes
clusterrole.rbac.authorization.k8s.io/pvviewer-role created

kubectl get clusterrole | grep pvviewer-role

kubectl create clusterrolebinding pvviewer-role-binding --clusterrole=pvviewer-role --serviceaccount=default:pvviewer


kubectl get po non-root-pod -oyaml

kubectl run curl --image=alpine/curl --rm -it -- sh
curl np-test-service

kubectl taint nodes foo dedicated=special-user:NoSchedule

kubectl taint nodes node01 env_type=production:NoSchedule
node/node01 tainted




kubectl scale rs new-replica-set --replicas=5

kubectl run redis --image=redis:alpine -l=tier=db
pod/redis created



kubectl expose deployment hr-web-app --name=hr-web-app-service --type=NodePort --port=8080
Examples:
  # Create a new ClusterIP service named my-cs
  kubectl create service clusterip my-cs --tcp=5678:8080
  
  # Create a new ClusterIP service named my-cs (in headless mode)
  kubectl create service clusterip my-cs --clusterip="None"
  
  



kubectl logs webapp-1






ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/etcd/server.crt --key=/etc/kubernetes/pki/etcd/server.key \
  snapshot save /opt/snapshot-pre-boot.db

export ETCDCTL_API=3 etcdctl --data-dir /var/lib/etcd-from-backup snapshot restore /opt/snapshot-pre-boot.db

kubectl config view
kubectl config get-clusters
NAME
cluster1
cluster2

kubectl config use-context cluster1
Switched to context "cluster1"

etcd-server ~ ➜  ps -ef | grep etcd
etcd         832       1  0 05:47 ?        00:00:50 /usr/local/bin/etcd --name etcd-server --data-dir=/var/lib/etcd-data --cert-file=/etc/etcd/pki/etcd.pem --key-file=/etc/etcd/pki/etcd-key.pem --peer-cert-file=/etc/etcd/pki/etcd.pem --peer-key-file=/etc/etcd/pki/etcd-key.pem --trusted-ca-file=/etc/etcd/pki/ca.pem --peer-trusted-ca-file=/etc/etcd/pki/ca.pem --peer-client-cert-auth --client-cert-auth --initial-advertise-peer-urls https://192.9.253.3:2380 --listen-peer-urls https://192.9.253.3:2380 --advertise-client-urls https://192.9.253.3:2379 --listen-client-urls https://192.9.253.3:2379,https://127.0.0.1:2379 --initial-cluster-token etcd-cluster-1 --initial-cluster etcd-server=https://192.9.253.3:2380 --initial-cluster-state new
root        1245     982  0 06:35 pts/0    00:00:00 grep etcd




cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep "\-\-etcd"
    - --etcd-cafile=/etc/kubernetes/pki/ca.crt
    - --etcd-certfile=/etc/kubernetes/pki/apiserver-etcd-client.crt
    - --etcd-keyfile=/etc/kubernetes/pki/apiserver-etcd-client.key
    - --etcd-servers=https://127.0.0.1:2379






kubectl create role developer --verb=list,create,delete --resource=pods
role.rbac.authorization.k8s.io/developer created

kubectl create rolebinding dev-user-binding --namespace=default --role=developer  --user=dev-user

kubectl get clusterroles --no-headers | wc -l

kubectl get clusterrolebindings --no-headers | wc -l
55

kubectl describe clusterrolebinding cluster-admin
Name:         cluster-admin
Labels:       kubernetes.io/bootstrapping=rbac-defaults
Annotations:  rbac.authorization.kubernetes.io/autoupdate: true
Role:
  Kind:  ClusterRole
  Name:  cluster-admin
Subjects:
  Kind   Name            Namespace
  ----   ----            ---------
  Group  system:masters  
  
  kubectl describe clusterrole cluster-admin 
Name:         cluster-admin
Labels:       kubernetes.io/bootstrapping=rbac-defaults
Annotations:  rbac.authorization.kubernetes.io/autoupdate: true
PolicyRule:
  Resources  Non-Resource URLs  Resource Names  Verbs
  ---------  -----------------  --------------  -----
  *.*        []                 []              [*]
             [*]                []              [*]
             


Tell me and I forget. Teach me and I remember. Involve me and I learn.

– Benjamin Franklin

kubectl create secret generic db-user-pass \
    --from-literal=username=admin \
    --from-literal=password='S!B\*d$zDsb='


kubectl create secret docker-registry private-reg-cred \
  --docker-server=myprivateregistry.com:5000 \
  --docker-username=dock_user \
  --docker-password=dock_password \
  --docker-email=dock_user@myprivateregistry.com


For success attitude is equally important as ability.

– Harry F.Bank




The beautiful thing about learning is that nobody can take it away from you.



netstat -nplt | grep scheduler

netstat -anp | grep etcd

ps -aux | grep kubelet
root        3553  0.0  0.1 1040228 307412 ?      Ssl  01:09   0:28 kube-apiserver --advertise-address=192.10.58.3 --allow-privileged=true --authorization-mode=Node,RBAC --client-ca-file=/etc/kubernetes/pki/ca.crt --enable-admission-plugins=NodeRestriction --enable-bootstrap-token-auth=true --etcd-cafile=/etc/kubernetes/pki/etcd/ca.crt --etcd-certfile=/etc/kubernetes/pki/apiserver-etcd-client.crt --etcd-keyfile=/etc/kubernetes/pki/apiserver-etcd-client.key --etcd-servers=https://127.0.0.1:2379 --kubelet-client-certificate=/etc/kubernetes/pki/apiserver-kubelet-client.crt --kubelet-client-key=/etc/kubernetes/pki/apiserver-kubelet-client.key --kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname --proxy-client-cert-file=/etc/kubernetes/pki/front-proxy-client.crt --proxy-client-key-file=/etc/kubernetes/pki/front-proxy-client.key --requestheader-allowed-names=front-proxy-client --requestheader-client-ca-file=/etc/kubernetes/pki/front-proxy-ca.crt --requestheader-extra-headers-prefix=X-Remote-Extra- --requestheader-group-headers=X-Remote-Group --requestheader-username-headers=X-Remote-User --secure-port=6443 --service-account-issuer=https://kubernetes.default.svc.cluster.local --service-account-key-file=/etc/kubernetes/pki/sa.pub --service-account-signing-key-file=/etc/kubernetes/pki/sa.key --service-cluster-ip-range=10.96.0.0/12 --tls-cert-file=/etc/kubernetes/pki/apiserver.crt --tls-private-key-file=/etc/kubernetes/pki/apiserver.key
root        4516  0.0  0.0 3700748 100756 ?      Ssl  01:09   0:12 /usr/bin/kubelet --bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf --kubeconfig=/etc/kubernetes/kubelet.conf --config=/var/lib/kubelet/config.yaml --container-runtime-endpoint=unix:///var/run/containerd/containerd.sock --pod-infra-container-image=registry.k8s.io/pause:3.9
root        8091  0.0  0.0   6744   656 pts/0    S+   01:18   0:00 grep --color=auto kubelet


controlplane /etc/cni/net.d ➜  cd /opt/cni/bin/

controlplane /opt/cni/bin ➜  ls
bandwidth  dhcp   firewall  host-device  ipvlan    macvlan  ptp  static  vlan
bridge     dummy  flannel   host-local   loopback  portmap  sbr  tuning  vrf






kubectl get ingress --all-namespaces


controlplane ~ ➜  kubectl describe ingress -n=app-space
Name:             ingress-wear-watch
Labels:           <none>
Namespace:        app-space
Address:          10.103.104.134
Ingress Class:    <none>
Default backend:  <default>
Rules:
  Host        Path  Backends
  ----        ----  --------
  *           
              /wear    wear-service:8080 (10.244.0.5:8080)
              /watch   video-service:8080 (10.244.0.4:8080)
Annotations:  nginx.ingress.kubernetes.io/rewrite-target: /
              nginx.ingress.kubernetes.io/ssl-redirect: false
Events:
  Type    Reason  Age                    From                      Message
  ----    ------  ----                   ----                      -------
  Normal  Sync    5m14s (x2 over 5m14s)  nginx-ingress-controller  Scheduled for sync
  
  
  









ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/etcd/server.crt --key=/etc/kubernetes/pki/etcd/server.key \
  snapshot save /opt/etcd-backup.db








kubectl get deploy -n=admin2406 -o \
  jsonpath='{.items[*].metadata.labels.version}'


kubectl -n admin2406 get deployment -o custom-columns=DEPLOYMENT:.metadata.name,CONTAINER_IMAGE:.spec.template.spec.containers[].image,READY_REPLICAS:.status.readyReplicas,NAMESPACE:.metadata.namespace --sort-by=.metadata.name > /opt/admin2406_data


ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/etcd/server.crt --key=/etc/kubernetes/pki/etcd/server.key \
  snapshot save /opt/cluster1_backup.db
  

kubectl create clusterrolebinding deploy-role-binding-cka20-arch --clusterrole=deploy-role-cka20-arch --serviceaccount=deploy-cka20-arch

kubectl create clusterrolebinding deploy-role-binding-cka20-arch --clusterrole=deploy-role-cka20-arch --serviceaccount=default:deploy-cka20-arch
clusterrolebinding.rbac.authorization.k8s.io/deploy-role-binding-cka20-arch created


---

# To Create user and approve his certificates
cat akshay.csr | base64 -w 0
cat akshay.csr | base64 | tr -d "\n"
kubectl get csr
kubectl certificate approve akshay
certificatesigningrequest.certificates.k8s.io/akshay approved

# To Deny CSR
kubectl get csr agent-smith -oyaml

apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  creationTimestamp: "2023-11-14T12:53:02Z"
  name: agent-smith
  resourceVersion: "1408"
  uid: d4b0eff6-6669-461f-ab04-732706980de0
spec:
  groups:
  - system:masters
  - system:authenticated
  request: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ1dEQ0NBVUFDQVFBd0V6RVJNQThHQTFVRUF3d0libVYzTFhWelpYSXdnZ0VpTUEwR0NTcUdTSWIzRFFFQgpBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRRE8wV0pXK0RYc0FKU0lyanBObzV2UklCcGxuemcrNnhjOStVVndrS2kwCkxmQzI3dCsxZUVuT041TXVxOTlOZXZtTUVPbnJEVU8vdGh5VnFQMncyWE5JRFJYall5RjQwRmJtRCs1eld5Q0sKeTNCaWhoQjkzTUo3T3FsM1VUdlo4VEVMcXlhRGtuUmwvanYvU3hnWGtvazBBQlVUcFdNeDRCcFNpS2IwVSt0RQpJRjVueEF0dE1Wa0RQUTdOYmVaUkc0M2IrUVdsVkdSL3o2RFdPZkpuYmZlek90YUF5ZEdMVFpGQy93VHB6NTJrCkVjQ1hBd3FDaGpCTGt6MkJIUFI0Sjg5RDZYYjhrMzlwdTZqcHluZ1Y2dVAwdEliT3pwcU52MFkwcWRFWnB3bXcKajJxRUwraFpFV2trRno4MGxOTnR5VDVMeE1xRU5EQ25JZ3dDNEdaaVJHYnJBZ01CQUFHZ0FEQU5CZ2txaGtpRwo5dzBCQVFzRkFBT0NBUUVBUzlpUzZDMXV4VHVmNUJCWVNVN1FGUUhVemFsTnhBZFlzYU9SUlFOd0had0hxR2k0CmhPSzRhMnp5TnlpNDRPT2lqeWFENnRVVzhEU3hrcjhCTEs4S2czc3JSRXRKcWw1ckxaeTlMUlZyc0pnaEQ0Z1kKUDlOTCthRFJTeFJPVlNxQmFCMm5XZVlwTTVjSjVURjUzbGVzTlNOTUxRMisrUk1uakRRSjdqdVBFaWM4L2RoawpXcjJFVU02VWF3enlrcmRISW13VHYybWxNWTBSK0ROdFYxWWllKzBIOS9ZRWx0K0ZTR2poNUw1WVV2STFEcWl5CjRsM0UveTNxTDcxV2ZBY3VIM09zVnBVVW5RSVNNZFFzMHFXQ3NiRTU2Q0M1RGhQR1pJcFVibktVcEF3a2ErOEUKdndRMDdqRytocGtueG11RkFlWHhnVXdvZEFMYUo3anUvVERJY3c9PQotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0K
  signerName: kubernetes.io/kube-apiserver-client
  usages:
  - digital signature
  - key encipherment
  - server auth
  username: agent-x
status: {}

kubectl certificate deny <certificate-signing-request-name>
kubectl delete csr agent-smith
certificatesigningrequest.certificates.k8s.io "agent-smith" deleted

kubectl get po --as dev-user

# Create Namespace command
kubectl create ns apx-x9984574

# To Switch Namespace
kubectl config set-context --current --namespace=alpha-mysql

# to access broken kubeconfig
kubectl config use-context research --kubeconfig /root/my-kube-config
kubectl config --kubeconfig /root/my-kube-config

# Cluster Nodes

# To Get Information on Nodes
kubectl get no
kubectl get no -o wide


kubectl run nginx --image=nginx; kubectl get po -o wide
curl http://10.10.0.4

nerdctl -n=k8s.io ps -a


kubenetes POD DNS Format

<podname>.<namespace>.pod.cluster.local
10-10-0-50.default.pod.cluster.local

kubectl run curl --image=curlimages/curl --restart=Never -- sh -c "sleep infinity"
kubectl exec -it curl -- sh -c "curl example.com"
kubectl exec -it curl -- sh -c "nslookup example.com"


k run temp --image=nginx:alpine --restart=Never --rm -i -- curl -m 5 nginx-service:8080
k run temp --image=nginx:alpine --restart=Never --rm -i -- curl -m 5 nginx



kcurl() { kubectl exec -it curl -- sh -c "curl $1"; }
knslookup() { kubectl exec -it curl -- sh -c "nslookup $1"; }

kcurl example.com
knslookup example.com

kcurl nginx.default.svc.cluster.local
knslookup 10-10-0-50.default.cluster.local


kubectl describe no controlplane | vi -

vim .vimrc
set ts=2 sts=2 sw=2 et nu ai cuc cul

cat /etc/kubernetes/manifests/etcd.yaml | grep file

kubectl get no -o json | jq -c 'paths'
kubectl get no -o json | jq -c 'paths'| grep type | grep -v condition

kubectl get no -o jsonpath='{.items[0].status.address}' | jq


culster maintenance - revision - DEC 3
k describe no | grep -i taints
cat /var/log/syslog | grep kube-apiserver

crictl ps -a
ps -aux | grep kubelet

k get po -A --sort-by=.metadata.creationTimestamps
k get po -A --sort-by=.metadata.creationTimestamps | tac
echo "k get po -A --sort-by=.metadata.creationTimestamps | tac" > /opt/pods_asc.sh
chmod +x /opt/pods_asc.sh

kubectl get no -o jsonpath='{.items[*].status.nodeInfo.osImage}' > file name


echo 'VGhpcyBpcyB0aGUgc2VjcmV0IQo=' | base64 --decode
alias check="k get deploy,svc,rs,po"
alias replace="k --grace-period=0 replace --force"


alias replace="k --grace-period=0 replace --force -f"
alias check="k get deploy,svc,rs,ds,po"
alias check="k get deploy,svc,rs,ds,po,secrets,pv,pvc,netpol"
alias check="k get deploy,svc,rs,ds,po,secrets,pv,pvc"

dr='--dry-run=client -o yaml'
fd='--force --grace-period=0'

apt-get update && apt-get install -y kubeadm='1.27.0-00' && \
apt-mark hold kubeadm

apt-mark unhold kubelet kubectl && \
apt-get update && apt-get install -y kubelet='1.27.0-00' kubectl='1.27.0-00' && \
apt-mark hold kubelet kubectl


ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/etcd/server.crt --key=/etc/kubernetes/pki/etcd/server.key \
  snapshot save /opt/cluster1.db
  
ETCDCTL_API=3 etcdctl --data-dir /var/lib/etcd-from-backup snapshot restore /opt/snapshot-pre-boot.db


student-node ~ ✖ kubectl config get-clusters
NAME
cluster1
cluster2

student-node ~ ➜  kubectl config use-context cluster1
Switched to context "cluster1".


etcd-server ~ ➜  systemctl status etcd
● etcd.service - etcd key-value store
   Loaded: loaded (/etc/systemd/system/etcd.service; enabled; vendor preset: enabled)
   Active: active (running) since Sun 2023-12-03 06:36:27 UTC; 58min ago
     Docs: https://github.com/etcd-io/etcd
 Main PID: 813 (etcd)
    Tasks: 37 (limit: 251379)
   CGroup: /system.slice/etcd.service
           └─813 /usr/local/bin/etcd --name etcd-server --data-dir=/var/lib/etcd-data --cert-file=/et
c/etcd/pki/etcd.pem --key-file=/etc/etcd/pki/etcd-key.pem --peer-cert-file=/etc/etcd/pki/etcd.pem --p
eer-key-file=/etc/etcd/pki/etcd-key.pem --trusted-ca-file=/etc/etcd/pki/ca.pem --peer-trusted-ca-file
=/etc/etcd/pki/ca.pem --peer-client-cert-auth --client-cert-auth --initial-advertise-peer-urls https:
//192.9.114.6:2380 --listen-peer-urls https://192.9.114.6:2380 --advertise-client-urls https://192.9.
114.6:2379 --listen-client-urls https://192.9.114.6:2379,https://127.0.0.1:2379 --initial-cluster-tok
en etcd-cluster-1 --initial-cluster etcd-server=https://192.9.114.6:2380 --initial-cluster-state new


ETCDCTL_API=3 etcdctl --endpoints 192.9.114.6:2379 \
  --cert=/etc/etcd/pki/etcd.pem \
  --key=/etc/etcd/pki/etcd-key.pem \
  --cacert=/etc/etcd/pki/ca.pem \
  member list

chown -R etcd.etcd etcd-data-restore-from-backup
etcd-server /var/lib ➜  vi /etc/systemd/system/etcd.service 

etcd-server /var/lib ➜  vi /etc/systemd/system/etcd.service 

etcd-server /var/lib ➜  systemctl daemon-reload 

etcd-server /var/lib ➜  systemctl restart etcd

kubectl get no -o jsonpath='{.items[*].status.nodeInfo.osImage}' > file name

kubectl get no -o jsonpath='{.items[*].status.nodeInfo.osImage}'




# Metrics Server Resource Ussage
kubectl top no > /opt/course/7/node.sh
kubectl top po --containers=true > /opt/course/7/pod.sh


# To Check Taints on Cluster Nodes
kubectl describe no controlplane | grep -i taint
kubectl describe no node01 | grep -i taint

# Add a Taint on Cluster Node
kubectl taint node controlplane env_type=production:NoSchedule
kubectl taint node node01 env_type=highcpu:NoSchedule

# Add Labels on Cluster Nodes
kubectl get no --show-labels
kubectl label no controlplane node=controlplane
kubectl label no node01 node=node01
kubectl label no node01 color=blue


# Show Pods
kubectl get po
kubectl get po -A
kubectl get all -A

# Nodes and Pods Labels
kubectl get po --show-labels -n=hr
kubectl get po --show-labels
kubectl get no node01  --show-labels
kubectl get no controlplane  --show-labels


# Simply Create Container command
kubectl run nginx-pod --image=nginx:alpine
kubectl run custom-nginx --image=nginx --port=8080

# Simply Create Container command but in selected namespace
kubectl run temp-bus --image=redis:alpine -n=finance

# Simply Create Container Command and add Labels 
kubectl run messaging --image=redis:alpine -l tier=msg

#  Container with Args
kubectl run webapp-green --image=kodekloud/webapp-color -- --color green

# Creating Static Pods Through Dry-Run File in Manifests Folder
kubectl run static-busybox --image=busybox --command -o yaml --dry-run=client -- sleep 1000 > /etc/kubernetes/manifests/.

# Repalce Command
kubectl replace --force -f /tmp/kubectl-edit-1568720089.yaml --grace-period=0

# Create Deployment
kubectl create deploy hr-web-app --image=kodekloud/webapp-color --replicas=2
kubectl create deploy redis-deploy --image=redis --replicas=2

# Set Image to change the image on deplpoyment
kubectl set image deployment/nginx-deploy  nginx=nginx:1.17

# Scale replicas on deployment
kubectl scale --current-replicas=1 --replicas=2 deployment app-wl01

# Show Services
kubectl get svc
kubectl get svc -n=production
kubectl get svc -A



# Create Expose Command for Cluster IP Service
kubectl expose po messaging --port=6379 --name=messaging-service

# Create Expose Command for NodePort Service
kubectl expose deployment hr-web-app --name=hr-web-app-service --type=NodePort --port=8080

# FOR HPA
kubectl -n=production autoscale deploy frontend --min=3 --max=5 --cpu-percent=80
kubectl get hpa -n=production

# Create ConfigMaps
kubectl create configmap my-config --from-literal=key1=config1 --from-literal=key2=config2
kubectl create configmap webapp-wl10-config-map --from-literal=APP_COLOR=red

# Secrets

# Show Secrets
kubectl get secert
kubectl get secert -n=production

kubectl create secret -h
Create a secret using specified subcommand.

# Available Commands:
  docker-registry   Create a secret for use with a Docker registry
  generic           Create a secret from a local file, directory, or literal value
  tls               Create a TLS secret

kubectl create secret docker-registry private-reg-cred --docker-server=myprivateregistry.com:5000 --docker-username=dock_user --docker-password=dock_password --docker-email=dock_user@myprivateregistry.com


# Create Generic Secrets
kubectl create secret generic db-secret --from-literal=DB_Host=sql01 --from-literal=DB_User=root --from-literal=DB_Password=password123
kubectl create secret generic secure-sec-cka12-arch --from-literal=color=darkblue -n=secure-sys-cka12-arch

# Create Service Account and allow all in core groups
kubectl --context cluster1 create serviceaccount pink-sa-cka24-arch
kubectl --context cluster1 create clusterrole pink-role-cka24-arch --resource=* --verb=*
kubectl --context cluster1 create clusterrolebinding pink-role-binding-cka24-arch --clusterrole=pink-role-cka24-arch --serviceaccount=default:pink-sa-cka24-arch

# To Decode the password
echo 'VGhpcyBpcyB0aGUgc2VjcmV0IQo=' | base64 --decode

# Create Service Account
kubectl create sa dashboard-sa
kubectl create token dashboard-sa

# Get All Roles
kubectl get sa,role,rolebinding -n=production

kubectl get clusterroles -A --no-headers | wc -l 
70
kubectl get clusterrolebinding -A --no-headers | wc -l 
55
kubectl auth can-i list nodes --as michelle



# To Execute Commands on Containers
kubectl exec -it busybox -- ip add
kubectl exec -it busybox -- ip route
kubectl exec -it app -- cat /log/app.log
kubectl exec ubuntu-sleeper -- whoami
root

kubectl run mycurlpod --image=curlimages/curl -i --tty -- sh

kubectl -n=gamma exec -it mycurlpod -- sh
~ $ 



# ETCD Backup

# Get all Certification Parameters from etcd port or etcd yaml file
vi /etc/kubernetes/manifests/etcd.yaml

ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/etcd/server.crt --key=/etc/kubernetes/pki/etcd/server.key \
  snapshot save /opt/etcd-backup.db

# Remote ETCD Server

ETCDCTL_API=3 etcdctl --endpoints https://192.9.253.3:2379 \
  --cert=/etc/etcd/pki/etcd.pem \
  --key=/etc/etcd/pki/etcd-key.pem \
  --cacert=/etc/etcd/pki/ca.pem \
  member list

# Remote ETCD Server Restoration
ETCDCTL_API=3 etcdctl --data-dir /var/lib/etcd-data-new snapshot restore /opt/cluster2.db
cd /var/lib/
ls -la 
chown -R etcd:etcd etcd-data-new/
vi /etc/systemd/system/etcd.service 
sudo systemctl daemon-reload
systemctl restart etcd


# jsonpath

# Get the list of nodes in JSON format and store it in a file at /opt/outputs/nodes-z3444kd9.json

kubectl get nodes -o json > /opt/outputs/nodes-z3444kd9.json

# Use JSON PATH query to retrieve the osImages of all the nodes and store it in a file /opt/outputs/nodes_os_x43kj56.txt.
# The osImages are under the nodeInfo section under status of each node.

kubectl get nodes -o jsonpath='{.items[*].status.nodeInfo.osImage}' > /opt/outputs/nodes_os_x43kj56.txt


# when Cluster is not responding
crictl ps -a | grep kube-apiserver
cbb3a949d5514       6f707f569b572       2 minutes ago        Exited              kube-apiserver            6                   eac4fc971b66e       kube-apiserver-controlplane



# To check kubelet service on node01 or node02
sudo systemctl status kubelet
sudo systemctl start kubelet
sudo systemctl restart kubelet
sudo systemctl daemon-reload


ps -aux | grep kubelet


# To check kubelet logs
journalctl -u kubelet -f

# To check Pod Logs
kubectl logs blue-dp-cka09-trb-xxxx -c init-container
kubectl get event --field-selector involvedObject.name=blue-dp-cka09-trb-xxxxx


# Storage Section

# To check Storage Class
kubectl get sc
NAME                   PROVISIONER             RECLAIMPOLICY   VOLUMEBINDINGMODE      ALLOWVOLUMEEXPANSION   AGE
local-path (default)   rancher.io/local-path   Delete          WaitForFirstConsumer   false 

# create PV with HostPath

apiVersion: v1
kind: PersistentVolume
metadata:
  name: pv-log
spec:
  persistentVolumeReclaimPolicy: Retain
  capacity:
    storage: 100Mi
  accessModes:
    - ReadWriteMany
  hostPath:
    path: "/pv/log"

# Create PVC for Local Storage Class

apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: local-pvc
spec:
  storageClassName: local-storage
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 500Mi



# Kubeadm upgrade

# add tolerations on Deployments or Pods if manadated

tolerations:
- key: "node-role.kubernetes.io/control-plane"
  operator: "Exists"
  effect: "NoSchedule"


# Second Upgrade controlplane
apt update
apt-mark unhold kubeadm && \
apt-get update && apt-get install -y kubeadm='1.27.0-00' && \
apt-mark hold kubeadm

kubeadm version
kubeadm upgrade plan

kubectl drain controlplane --ignore-daemonsets

apt-mark unhold kubelet kubectl && \
apt-get update && apt-get install -y kubelet='1.27.0-00' kubectl='1.27.0-00' && \
apt-mark hold kubelet kubectl

sudo systemctl daemon-reload
sudo systemctl restart kubelet

kubectl uncordon controlplane

# Third upgrade Node01, Node02

apt update
apt-mark unhold kubeadm && \
apt-get update && apt-get install -y kubeadm='1.27.0-00' && \
apt-mark hold kubeadm
kubectl drain node01 --ignore-daemonsets
apt-mark unhold kubelet kubectl && \
apt-get update && apt-get install -y kubelet='1.27.0-00' kubectl='1.27.0-00' && \
apt-mark hold kubelet kubectl

sudo systemctl daemon-reload
sudo systemctl restart kubelet

kubectl uncordon node01



# Imperative commands create
controlplane ~ ➜  kubectl create 
clusterrolebinding   (Create a cluster role binding for a particular cluster role)
clusterrole          (Create a cluster role)
configmap            (Create a config map from a local file, directory or literal value)
cronjob              (Create a cron job with the specified name)
deployment           (Create a deployment with the specified name)
ingress              (Create an ingress with the specified name)
job                  (Create a job with the specified name)
namespace            (Create a namespace with the specified name)
poddisruptionbudget  (Create a pod disruption budget with the specified name)
priorityclass        (Create a priority class with the specified name)
quota                (Create a quota with the specified name)
rolebinding          (Create a role binding for a particular role or cluster role)
role                 (Create a role with single rule)
secret               (Create a secret using specified subcommand)
serviceaccount       (Create a service account with the specified name)
service              (Create a service using a specified subcommand)
token                (Request a service account token)


# Network Policy


apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: internal-policy
  namespace: default
spec:
  podSelector:
    matchLabels:
      name: internal
  policyTypes:
    - Egress
    - Ingress
  ingress:
  - {}
  egress:
    - to:
      - podSelector:
            matchLabels:
              name: payroll
      ports:
        - protocol: TCP
          port: 8080
    - to:
      - podSelector:
            matchLabels:
              name: mysql
      ports:
        - protocol: TCP
          port: 3306

    - ports:
      - port: 53
        protocol: UDP
      - port: 53
        protocol: TCP
        
# Flannel Specific

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

annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
    nginx.ingress.kubernetes.oi/ssl-redirect: "false"

---

SECTION: ARCHITECTURE, INSTALL AND MAINTENANCE


For this question, please set the context to cluster3 by running:


kubectl config use-context cluster3


Decode the existing secret called beta-sec-cka14-arch created in the beta-ns-cka14-arch namespace and store the decoded content inside the file /opt/beta-sec-cka14-arch on the student-node.


SECTION: ARCHITECTURE, INSTALL AND MAINTENANCE


For this question, please set the context to cluster3 by running:


kubectl config use-context cluster3


Run a pod called alpine-sleeper-cka15-arch using the alpine image in the default namespace that will sleep for 7200 seconds.


SECTION: ARCHITECTURE, INSTALL AND MAINTENANCE


For this question, please set the context to cluster3 by running:


kubectl config use-context cluster3

Create a generic secret called secure-sec-cka12-arch in the secure-sys-cka12-arch namespace on the cluster3. Use the key/value of color=darkblue to create the secret.


SECTION: ARCHITECTURE, INSTALL AND MAINTENANCE


Find the pod that consumes the most memory and store the result to the file /opt/high_memory_pod in the following format cluster_name,namespace,pod_name.

The pod could be in any namespace in any of the clusters that are currently configured on the student-node.

NOTE: It's recommended to wait for a few minutes to allow deployed objects to become fully operational and start consuming resources.



Check out the metrics for all pods across all clusters:

student-node ~ ➜  kubectl top pods -A --context cluster1 --no-headers | sort -nr -k4 | head -1
kube-system       kube-apiserver-cluster1-controlplane            48m   262Mi   

student-node ~ ➜  kubectl top pods -A --context cluster2 --no-headers | sort -nr -k4 | head -1
kube-system   kube-apiserver-cluster2-controlplane            44m   258Mi   

student-node ~ ➜  kubectl top pods -A --context cluster3 --no-headers | sort -nr -k4 | head -1
default       backend-cka06-arch                        205m   596Mi   

student-node ~ ➜  kubectl top pods -A --context cluster4 --no-headers | sort -nr -k4 | head -1
kube-system   kube-apiserver-cluster4-controlplane            43m   266Mi   

student-node ~ ➜  



Using this, find the pod that uses most memory. In this case, it is backend-cka06-arch on cluster3.


Save the result in the correct format to the file:

student-node ~ ➜  echo cluster3,default,backend-cka06-arch > /opt/high_memory_pod

SECTION: ARCHITECTURE, INSTALL AND MAINTENANCE
For this question, please set the context to cluster3 by running:

kubectl config use-context cluster3

A pod called logger-complete-cka04-arch has been created in the default namespace. Inspect this pod and save ALL the logs to the file /root/logger-complete-cka04-arch on the student-node.

SECTION: TROUBLESHOOTING
For this question, please set the context to cluster1 by running:

kubectl config use-context cluster1

A template to create a Kubernetes pod is stored at /root/red-probe-cka12-trb.yaml on the student-node. However, using this template as-is is resulting in an error.
Fix the issue with this template and use it to create the pod. Once created, watch the pod for a minute or two to make sure its stable i.e, it's not crashing or restarting.


Make sure you do not update the args: section of the template.

Solution: 

# Try to apply the template

kubectl apply -f red-probe-cka12-trb.yaml 

# You will see error:

error: error validating "red-probe-cka12-trb.yaml": error validating data: [ValidationError(Pod.spec.containers[0].livenessProbe.httpGet): unknown field "command" in io.k8s.api.core.v1.HTTPGetAction, ValidationError(Pod.spec.containers[0].livenessProbe.httpGet): missing required field "port" in io.k8s.api.core.v1.HTTPGetAction]; if you choose to ignore these errors, turn validation off with --validate=false

# From the error you can see that the error is for liveness probe, so let's open the template to find out:

vi red-probe-cka12-trb.yaml

# Under livenessProbe: you will see the type is httpGet however the rest of the options are command based so this probe should be of exec type.

Change httpGet to exec

# Try to apply the template now

kubectl apply -f red-probe-cka12-trb.yaml 

# Cool it worked, now let's watch the POD status, after few seconds you will notice that POD is restarting. So let's check the logs/events

kubectl get event --field-selector involvedObject.name=red-probe-cka12-trb

# You will see an error like:

21s         Warning   Unhealthy   pod/red-probe-cka12-trb   Liveness probe failed: cat: can't open '/healthcheck': No such file or directory

# So seems like Liveness probe is failing, lets look into it:

vi red-probe-cka12-trb.yaml

# Notice the command - sleep 3 ; touch /healthcheck; sleep 30;sleep 30000 it starts with a delay of 3 seconds, but the liveness probe initialDelaySeconds is set to 1 and failureThreshold is also 1. Which means the POD will fail just after first attempt of liveness check which will happen just after 1 second of pod start. So to make it stable we must increase the initialDelaySeconds to at least 5


vi red-probe-cka12-trb.yaml

# Change initialDelaySeconds from 1 to 5 and save apply the changes.
# Delete old pod:

kubectl delete pod red-probe-cka12-trb

Apply changes:

kubectl apply -f red-probe-cka12-trb.yaml


# SECTION: TROUBLESHOOTING
# For this question, please set the context to cluster1 by running:

kubectl config use-context cluster1

# We deployed an app using a deployment called web-dp-cka06-trb. it's using the httpd:latest image. There is a corresponding service called web-service-cka06-trb that exposes this app on the node port 30005. However, the app is not accessible!
# Troubleshoot and fix this issue. Make sure you are able to access the app using curl http://kodekloud-exam.app:30005 command.

Solution: 
# List the deployments to see if all PODs under web-dp-cka06-trb deployment are up and running.
kubectl get deploy
# You will notice that 0 out of 1 PODs are up, so let's look into the POD now.

kubectl get pod

# You will notice that web-dp-cka06-trb-xxx pod is in Pending state, so let's checkout the relevant events.
kubectl get event --field-selector involvedObject.name=web-dp-cka06-trb-xxx

# You should see some error/warning like this:
Warning   FailedScheduling   pod/web-dp-cka06-trb-76b697c6df-h78x4   0/1 nodes are available: 1 persistentvolumeclaim "web-cka06-trb" not found. preemption: 0/1 nodes are available: 1 Preemption is not helpful for scheduling.

# Let's look into the PVCs
kubectl get pvc
# You should see web-pvc-cka06-trb in the output but as per logs the POD was looking for web-cka06-trb PVC. Let's update the deployment to fix this.
kubectl edit deploy web-dp-cka06-trb
# Under volumes: -> name: web-str-cka06-trb -> persistentVolumeClaim: -> claimName change web-cka06-trb to web-pvc-cka06-trb and save the changes.

# Look into the POD again to make sure its running now
kubectl get pod

# You will find that its still failing, most probably with ErrImagePull or ImagePullBackOff error. Now lets update the deployment again to make sure its using the correct image.
kubectl edit deploy web-dp-cka06-trb

# Under spec: -> containers: -> change image from httpd:letest to httpd:latest and save the changes.
Look into the POD again to make sure its running now

kubectl get pod

# You will notice that POD is still crashing, let's look into the POD logs.
kubectl logs web-dp-cka06-trb-xxxx

# if there are no useful logs then look into the events
kubectl get event --field-selector involvedObject.name=web-dp-cka06-trb-xxxx --sort-by='.lastTimestamp'

# You should see some errors/warnings as below

Warning   FailedPostStartHook   pod/web-dp-cka06-trb-67dccb7487-2bjgf   Exec lifecycle hook ([/bin -c echo 'Test Page' > /usr/local/apache2/htdocs/index.html]) for Container "web-container" in Pod "web-dp-cka06-trb-67dccb7487-2bjgf_default(4dd6565e-7f1a-4407-b3d9-ca595e6d4e95)" failed - error: rpc error: code = Unknown desc = failed to exec in container: failed to start exec "c980799567c8176db5931daa2fd56de09e84977ecd527a1d1f723a862604bd7c": OCI runtime exec failed: exec failed: unable to start container process: exec: "/bin": permission denied: unknown, message: ""


# Let's look into the lifecycle hook of the pod

kubectl edit deploy web-dp-cka06-trb

# Under containers: -> lifecycle: -> postStart: -> exec: -> command: change /bin to /bin/sh

# Look into the POD again to make sure its running now
kubectl get pod

# Finally pod should be in running state. Let's try to access the webapp now.

curl http://kodekloud-exam.app:30005

# You will see error curl: (7) Failed to connect to kodekloud-exam.app port 30005: Connection refused
Let's look into the service

kubectl edit svc web-service-cka06-trb

# Let's verify if the selector labels and ports are correct as needed. You will note that service is using selector: -> app: web-cka06-trb
Now, let's verify the app labels:

# kubectl get deploy web-dp-cka06-trb -o yaml

Under labels you will see labels: -> deploy: web-app-cka06-trb

# So we can see that service is using wrong selector label, let's edit the service to fix the same

kubectl edit svc web-service-cka06-trb

Let's try to access the webapp now.

curl http://kodekloud-exam.app:30005

Boom! app should be accessible now.


SECTION: TROUBLESHOOTING
For this question, please set the context to cluster1 by running:
kubectl config use-context cluster1

# A YAML template for a Kubernetes deployment is stored at /root/app-cka07-trb.yaml. However, creating a deployment using this file is failing. Investigate the cause of the errors and fix the issue.
Make sure that the pod is in running state once deployed.
Note: Do not to make any changes in the template file.



SECTION: TROUBLESHOOTING
For this question, please set the context to cluster1 by running:
kubectl config use-context cluster1
# A pod called nginx-cka01-trb is running in the default namespace. There is a container called nginx-container running inside this pod that uses the image nginx:latest. There is another sidecar container called logs-container that runs in this pod.

# For some reason, this pod is continuously crashing. Identify the issue and fix it. Make sure that the pod is in a running state and you are able to access the website using the curl http://kodekloud-exam.app:30001 command on the controlplane node of cluster1


Solution:

# Check the container logs:
kubectl logs -f nginx-cka01-trb -c nginx-container
# You can see that its not able to pull the image.

# Edit the pod
kubectl edit pod nginx-cka01-trb -o yaml

# Change image tag from nginx:latst to nginx:latest
# Let's check now if the POD is in Running state

kubectl get pod

# You will notice that its still crashing, so check the logs again:
kubectl logs -f nginx-cka01-trb -c nginx-container

# From the logs you will notice that nginx-container is looking good now so it might be the sidecar container that is causing issues. Let's check its logs.

kubectl logs -f nginx-cka01-trb -c logs-container

# You will see some logs as below:

cat: can't open '/var/log/httpd/access.log': No such file or directory
cat: can't open '/var/log/httpd/error.log': No such file or directory

# Now, let's look into the sidecar container

kubectl get pod nginx-cka01-trb -o yaml

# Under containers: check the command: section, this is the command which is failing. If you notice its looking for the logs under /var/log/httpd/ directory but the mounted volume for logs is /var/log/nginx (under volumeMounts:). So we need to fix this path:

kubectl get pod nginx-cka01-trb -o yaml > /tmp/test.yaml

vi /tmp/test.yaml

# Under command: change /var/log/httpd/access.log and /var/log/httpd/error.log to /var/log/nginx/access.log and /var/log/nginx/error.log respectively.

# Delete the existing POD now:

kubectl delete pod nginx-cka01-trb

# Create new one from the template

kubectl apply -f /tmp/test.yaml
# Let's check now if the POD is in Running state

kubectl get pod

# It should be good now. So let's try to access the app.

curl http://kodekloud-exam.app:30001


You will see error

curl: (7) Failed to connect to kodekloud-exam.app port 30001: Connection refused


# So you are not able to access the website, let's look into the service configuration.

# Edit the service

kubectl edit svc nginx-service-cka01-trb -o yaml 
# Change app label under selector from httpd-app-cka01-trb to nginx-app-cka01-trb

# You should be able to access the website now.
curl http://kodekloud-exam.app:30001



SECTION: TROUBLESHOOTING
# For this question, please set the context to cluster4 by running:
kubectl config use-context cluster4

# There is some issue on the student-node preventing it from accessing the cluster4 Kubernetes Cluster.
# Troubleshoot and fix this issue. Make sure that you are able to run the kubectl commands (For example: kubectl get node --context=cluster4) from the student-node.
# The kubeconfig for all the clusters is stored in the default kubeconfig file: /root/.kube/config on the student-node.


SECTION: TROUBLESHOOTING
# For this question, please set the context to cluster2 by running:
kubectl config use-context cluster2
# The cat-cka22-trb pod is stuck in Pending state. Look into the issue to fix the same. Make sure that the pod is in running state and its stable (i.e not restarting or crashing).
# Note: Do not make any changes to the pod (No changes to pod config but you may destory and re-create).

Solution: 
# Let's check the POD status
kubectl get pod
# You will see that cat-cka22-trb pod is stuck in Pending state. So let's try to look into the events

kubectl --context cluster2 get event --field-selector involvedObject.name=cat-cka22-trb

# You will see some logs as below

Warning   FailedScheduling   pod/cat-cka22-trb   0/3 nodes are available: 1 node(s) had untolerated taint {node-role.kubernetes.io/master: }, 2 node(s) didn't match Pod's node affinity/selector. preemption: 0/2 nodes are available: 3 Preemption is not helpful for scheduling.

# So seems like this POD is using the node affinity, let's look into the POD to understand the node affinity its using.

kubectl --context cluster2 get pod cat-cka22-trb -o yaml

Under affinity: you will see its looking for key: node and values: cluster2-node02 so let's verify if node01 has these labels applied.

kubectl --context cluster2 get node cluster2-node01 -o yaml

Look under labels: and you will not find any such label, so let's add this label to this node.

kubectl label node cluster1-node01 node=cluster2-node01

Check again the node details

kubectl get node cluster2-node01 -o yaml

The new label should be there, let's see if POD is scheduled now on this node

kubectl --context cluster2 get pod

Its is but it must be crashing or restarting, so let's look into the pod logs
kubectl --context cluster2 logs -f cat-cka22-trb

---

SECTION: ARCHITECTURE, INSTALL AND MAINTENANCE


For this question, please set the context to cluster3 by running:


kubectl config use-context cluster3


Decode the existing secret called beta-sec-cka14-arch created in the beta-ns-cka14-arch namespace and store the decoded content inside the file /opt/beta-sec-cka14-arch on the student-node.



student-node ~ ➜  kubectl config use-context cluster3
Switched to context "cluster3".

student-node ~ ➜  kubectl get secret -n=beta-ns-cka14-arch
NAME                  TYPE     DATA   AGE
beta-sec-cka14-arch   Opaque   1      50s

student-node ~ ➜  kubectl describe secret beta-sec-cka14-arch -n=beta-ns-cka14-arch 
Name:         beta-sec-cka14-arch
Namespace:    beta-ns-cka14-arch
Labels:       <none>
Annotations:  <none>

Type:  Opaque

Data
====
secret:  20 bytes

student-node ~ ➜  kubectl edit secret beta-sec-cka14-arch -n=beta-ns-cka14-arch 
Edit cancelled, no changes made.

student-node ~ ➜  echo 'VGhpcyBpcyB0aGUgc2VjcmV0IQo=' | base64 --decode
This is the secret!

student-node ~ ➜  echo 'VGhpcyBpcyB0aGUgc2VjcmV0IQo=' | base64 --decode > /opt/beta-sec-cka14-arch

student-node ~ ➜ 


SECTION: ARCHITECTURE, INSTALL AND MAINTENANCE


Find the node across all clusters that consumes the most CPU and store the result to the file /opt/high_cpu_node in the following format cluster_name,node_name.

The node could be in any clusters that are currently configured on the student-node.

NOTE: It's recommended to wait for a few minutes to allow deployed objects to become fully operational and start consuming resources.


data stored in /opt/high_cpu_node?


kubectl top node sort-by=cpu' --context cluster1 --no-headers

Left incomplete


SECTION: ARCHITECTURE, INSTALL AND MAINTENANCE


For this question, please set the context to cluster2 by running:


kubectl config use-context cluster2


Install etcd utility on cluster2-controlplane node so that we can take/restore etcd backups.



You can ssh to the controlplane node by running ssh root@cluster2-controlplane from the student-node.

etcd utility installed on cluster2-controlplane node?



SECTION: ARCHITECTURE, INSTALL AND MAINTENANCE


For this question, please set the context to cluster1 by running:


kubectl config use-context cluster1


There is a script located at /root/pod-cka26-arch.sh on the student-node. Update this script to add a command to filter/display the label with value component of the pod called kube-apiserver-cluster1-controlplane (on cluster1) using jsonpath.



script updated?






SECTION: TROUBLESHOOTING


For this question, please set the context to cluster4 by running:


kubectl config use-context cluster4


The pink-depl-cka14-trb Deployment was scaled to 2 replicas however, the current replicas is still 1.


Troubleshoot and fix this issue. Make sure the CURRENT count is equal to the DESIRED count.


You can SSH into the cluster4 using ssh cluster4-controlplane command.

CURRENT count is equal to the DESIRED count?


SECTION: TROUBLESHOOTING


For this question, please set the context to cluster2 by running:


kubectl config use-context cluster2


The yello-cka20-trb pod is stuck in a Pending state. Fix this issue and get it to a running state. Recreate the pod if necessary.

Do not remove any of the existing taints that are set on the cluster nodes.



Node taints unchanged?

pod is running?



SECTION: SCHEDULING


For this question, please set the context to cluster3 by running:


kubectl config use-context cluster3


We have deployed a 2-tier web application on the cluster3 nodes in the canara-wl05 namespace. However, at the moment, the web app pod cannot establish a connection with the MySQL pod successfully.


You can check the status of the application from the terminal by running the curl command with the following syntax:

curl http://cluster3-controlplane:NODE-PORT



SECTION: SCHEDULING


For this question, please set the context to cluster1 by running:


kubectl config use-context cluster1


Create a deployment called app-wl01 using the nginx image and scale the application pods to 2.



Deployment is running?






student-node ~ ➜  kubectl top node --context cluster1 --no-headers | sort -nr -k2 | head -1
cluster1-controlplane   127m   1%    703Mi   1%    

student-node ~ ➜  kubectl top node --context cluster2 --no-headers | sort -nr -k2 | head -1
cluster2-controlplane   126m   1%    675Mi   1%    

student-node ~ ➜  kubectl top node --context cluster3 --no-headers | sort -nr -k2 | head -1
cluster3-controlplane   577m   7%    1081Mi   1%    

student-node ~ ➜  kubectl top node --context cluster4 --no-headers | sort -nr -k2 | head -1
cluster4-controlplane   130m   1%    679Mi   1%    

student-node ~ ➜  

student-node ~ ➜  


SECTION: ARCHITECTURE, INSTALL AND MAINTENANCE


For this question, please set the context to cluster2 by running:


kubectl config use-context cluster2


Install etcd utility on cluster2-controlplane node so that we can take/restore etcd backups.


You can ssh to the controlplane node by running ssh root@cluster2-controlplane from the student-node.


SSH into cluster2-controlplane node:

student-node ~ ➜ ssh root@cluster2-controlplane


Install etcd utility:

cluster2-controlplane ~ ➜ cd /tmp
cluster2-controlplane ~ ➜ export RELEASE=$(curl -s https://api.github.com/repos/etcd-io/etcd/releases/latest | grep tag_name | cut -d '"' -f 4)
cluster2-controlplane ~ ➜ wget https://github.com/etcd-io/etcd/releases/download/${RELEASE}/etcd-${RELEASE}-linux-amd64.tar.gz
cluster2-controlplane ~ ➜ tar xvf etcd-${RELEASE}-linux-amd64.tar.gz ; cd etcd-${RELEASE}-linux-amd64
cluster2-controlplane ~ ➜ mv etcd etcdctl  /usr/local/bin/


SECTION: ARCHITECTURE, INSTALL AND MAINTENANCE


For this question, please set the context to cluster1 by running:


kubectl config use-context cluster1


There is a script located at /root/pod-cka26-arch.sh on the student-node. Update this script to add a command to filter/display the label with value component of the pod called kube-apiserver-cluster1-controlplane (on cluster1) using jsonpath.


Update pod-cka26-arch.sh script:
student-node ~ ➜ vi pod-cka26-arch.sh

Add below command in it:

kubectl --context cluster1 get pod -n kube-system kube-apiserver-cluster1-controlplane  -o jsonpath='{.metadata.labels.component}'


For this question, please set the context to cluster3 by running:


kubectl config use-context cluster3


We have deployed a 2-tier web application on the cluster3 nodes in the canara-wl05 namespace. However, at the moment, the web app pod cannot establish a connection with the MySQL pod successfully.


You can check the status of the application from the terminal by running the curl command with the following syntax:



curl http://cluster3-controlplane:NODE-PORT
To make the application work, create a new secret called db-secret-wl05 with the following key values: -

1. DB_Host=mysql-svc-wl05
2. DB_User=root
3. DB_Password=password123


Next, configure the web application pod to load the new environment variables from the newly created secret.


Note: Check the web application again using the curl command, and the status of the application should be success.


You can SSH into the cluster3 using ssh cluster3-controlplane command.


Set the correct context: -

kubectl config use-context cluster3
List the nodes: -

kubectl get nodes -o wide

Run the curl command to know the status of the application as follows: -


ssh cluster2-controlplane

curl http://10.17.63.11:31020
<!doctype html>
<title>Hello from Flask</title>
...

    <img src="/static/img/failed.png">
    <h3> Failed connecting to the MySQL database. </h3>


    <h2> Environment Variables: DB_Host=Not Set; DB_Database=Not Set; DB_User=Not Set; DB_Password=Not Set; 2003: Can&#39;t connect to MySQL server on &#39;localhost:3306&#39; (111 Connection refused) </h2>
    

As you can see, the status of the application pod is failed.


NOTE: - In your lab, IP addresses could be different.



Let's create a new secret called db-secret-wl05 as follows: -

kubectl create secret generic db-secret-wl05 -n canara-wl05 --from-literal=DB_Host=mysql-svc-wl05 --from-literal=DB_User=root --from-literal=DB_Password=password123

After that, configure the newly created secret to the web application pod as follows: -

---
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: webapp-pod-wl05
  name: webapp-pod-wl05
  namespace: canara-wl05
spec:
  containers:
  - image: kodekloud/simple-webapp-mysql
    name: webapp-pod-wl05
    envFrom:
    - secretRef:
        name: db-secret-wl05

then use the kubectl replace command: -

kubectl replace -f <FILE-NAME> --force


In the end, make use of the curl command to check the status of the application pod. The status of the application should be success.

curl http://10.17.63.11:31020

<!doctype html>
<title>Hello from Flask</title>
<body style="background: #39b54b;"></body>
<div style="color: #e4e4e4;
    text-align:  center;
    height: 90px;
    vertical-align:  middle;">


    <img src="/static/img/success.jpg">
    <h3> Successfully connected to the MySQL database.</h3>
    

For this question, please set the context to cluster1 by running:


kubectl config use-context cluster1


Create a new deployment called ocean-tv-wl09 in the default namespace using the image kodekloud/webapp-color:v1.
Use the following specs for the deployment:


1. Replica count should be 3.

2. Set the Max Unavailable to 40% and Max Surge to 55%.

3. Create the deployment and ensure all the pods are ready.

4. After successful deployment, upgrade the deployment image to kodekloud/webapp-color:v2 and inspect the deployment rollout status.

5. Check the rolling history of the deployment and on the student-node, save the current revision count number to the /opt/revision-count.txt file.

6. Finally, perform a rollback and revert back the deployment image to the older version.



Set the correct context: -

kubectl config use-context cluster1


Use the following template to create a deployment called ocean-tv-wl09: -


---
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: ocean-tv-wl09
  name: ocean-tv-wl09
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ocean-tv-wl09
  strategy: 
   type: RollingUpdate
   rollingUpdate:
     maxUnavailable: 40%
     maxSurge: 55%
  template:
    metadata:
      labels:
        app: ocean-tv-wl09
    spec:
      containers:
      - image: kodekloud/webapp-color:v1
        name: webapp-color
        

Now, create the deployment by using the kubectl create -f command in the default namespace: -

kubectl create -f <FILE-NAME>.yaml

After sometime, upgrade the deployment image to kodekloud/webapp-color:v2: -

kubectl set image deploy ocean-tv-wl09 webapp-color=kodekloud/webapp-color:v2

And check out the rollout history of the deployment ocean-tv-wl09: -

kubectl rollout history deploy ocean-tv-wl09
deployment.apps/ocean-tv-wl09 
REVISION  CHANGE-CAUSE
1         <none>
2         <none>

NOTE: - Revision count is 2. In your lab, it could be different.



On the student-node, store the revision count to the given file: -

echo "2" > /opt/revision-count.txt



In final task, rollback the deployment image to an old version: -

kubectl rollout undo deployment ocean-tv-wl09


Verify the image name by using the following command: -

kubectl describe deploy ocean-tv-wl09


It should be kodekloud/webapp-color:v1 image.


SECTION: STORAGE


For this question, please set the context to cluster1 by running:


kubectl config use-context cluster1


A pod definition file is created at /root/peach-pod-cka05-str.yaml on the student-node. Update this manifest file to create a persistent volume claim called peach-pvc-cka05-str to claim a 100Mi of storage from peach-pv-cka05-str PV (this is already created). Use the access mode ReadWriteOnce.


Further add peach-pvc-cka05-str PVC to peach-pod-cka05-str POD and mount the volume at /var/www/html location. Ensure that the pod is running and the PV is bound.


Set context to cluster1

Update /root/peach-pod-cka05-str.yaml template file to create a PVC to utilise the same in POD template.


apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: peach-pvc-cka05-str
spec:
  volumeName: peach-pv-cka05-str
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 100Mi
---
apiVersion: v1
kind: Pod
metadata:
  name: peach-pod-cka05-str
spec:
  containers:
  - image: nginx
    name: nginx
    volumeMounts:
      - mountPath: "/var/www/html"
        name: nginx-volume
  volumes:
    - name: nginx-volume
      persistentVolumeClaim:
        claimName: peach-pvc-cka05-str


Apply the template:

kubectl apply -f /root/peach-pod-cka05-str.yaml

SECTION: STORAGE


For this question, please set the context to cluster1 by running:


kubectl config use-context cluster1


Create a storage class with the name banana-sc-cka08-str as per the properties given below:


- Provisioner should be kubernetes.io/no-provisioner,

- Volume binding mode should be WaitForFirstConsumer.

- Volume expansion should be enabled.

Create a yaml template as below:

kind: StorageClass
apiVersion: storage.k8s.io/v1
metadata:
  name: banana-sc-cka08-str
provisioner: kubernetes.io/no-provisioner
allowVolumeExpansion: true
volumeBindingMode: WaitForFirstConsumer

Apply the template:

kubectl apply -f <template-file-name>.yaml

SECTION: SERVICE NETWORKING


For this question, please set the context to cluster3 by running:


kubectl config use-context cluster3


We have an external webserver running on student-node which is exposed at port 9999. We have created a service called external-webserver-cka03-svcn that can connect to our local webserver from within the kubernetes cluster3 but at the moment it is not working as expected.



Fix the issue so that other pods within cluster3 can use external-webserver-cka03-svcn service to access the webserver.


Let's check if the webserver is working or not:


student-node ~ ➜  curl student-node:9999
...
<h1>Welcome to nginx!</h1>
...

Now we will check if service is correctly defined:

student-node ~ ➜  kubectl describe svc external-webserver-cka03-svcn 
Name:              external-webserver-cka03-svcn
Namespace:         default
.
.
Endpoints:         <none> # there are no endpoints for the service
...

As we can see there is no endpoints specified for the service, hence we won't be able to get any output. Since we can not destroy any k8s object, let's create the endpoint manually for this service as shown below:

student-node ~ ➜  export IP_ADDR=$(ifconfig eth0 | grep inet | awk '{print $2}')

student-node ~ ➜ kubectl --context cluster3 apply -f - <<EOF
apiVersion: v1
kind: Endpoints
metadata:
  # the name here should match the name of the Service
  name: external-webserver-cka03-svcn
subsets:
  - addresses:
      - ip: $IP_ADDR
    ports:
      - port: 9999
EOF


Finally check if the curl test works now:

student-node ~ ➜  kubectl --context cluster3 run --rm  -i test-curl-pod --image=curlimages/curl --restart=Never -- curl -m 2 external-webserver-cka03-svcn
...
<title>Welcome to nginx!</title>
...


SECTION: SERVICE NETWORKING


For this question, please set the context to cluster3 by running:


kubectl config use-context cluster3


Create a ReplicaSet with name checker-cka10-svcn in ns-12345-svcn namespace with image registry.k8s.io/e2e-test-images/jessie-dnsutils:1.3.


Make sure to specify the below specs as well:


command sleep 3600
replicas set to 2
container name: dns-image



Once the checker pods are up and running, store the output of the command nslookup kubernetes.default from any one of the checker pod into the file /root/dns-output-12345-cka10-svcn on student-node.


Change to the cluster4 context before attempting the task:

kubectl config use-context cluster3



Create the ReplicaSet as per the requirements:


kubectl apply -f - << EOF
---
apiVersion: v1
kind: Namespace
metadata:
  creationTimestamp: null
  name: ns-12345-svcn
spec: {}
status: {}

---
apiVersion: apps/v1
kind: ReplicaSet
metadata:
  name: checker-cka10-svcn
  namespace: ns-12345-svcn
  labels:
    app: dns
    tier: testing
spec:
  replicas: 2
  selector:
    matchLabels:
      tier: testing
  template:
    metadata:
      labels:
        tier: testing
    spec:
      containers:
      - name: dns-image
        image: registry.k8s.io/e2e-test-images/jessie-dnsutils:1.3
        command:
          - sleep
          - "3600"
EOF

Now let's test if the nslookup command is working :

student-node ~ ➜  k get pods -n ns-12345-svcn 
NAME                       READY   STATUS    RESTARTS   AGE
checker-cka10-svcn-d2cd2   1/1     Running   0          12s
checker-cka10-svcn-qj8rc   1/1     Running   0          12s

student-node ~ ➜  POD_NAME=`k get pods -n ns-12345-svcn --no-headers | head -1 | awk '{print $1}'`

student-node ~ ➜  kubectl exec -n ns-12345-svcn -i -t $POD_NAME -- nslookup kubernetes.default
;; connection timed out; no servers could be reached

command terminated with exit code 1


There seems to be a problem with the name resolution. Let's check if our coredns pods are up and if any service exists to reach them:


student-node ~ ➜  k get pods -n kube-system | grep coredns
coredns-6d4b75cb6d-cprjz                        1/1     Running   0             42m
coredns-6d4b75cb6d-fdrhv                        1/1     Running   0             42m

student-node ~ ➜  k get svc -n kube-system 
NAME       TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)                  AGE
kube-dns   ClusterIP   10.96.0.10   <none> 

Everything looks okay here but the name resolution problem exists, let's see if the kube-dns service have any active endpoints:



student-node ~ ➜  kubectl get ep -n kube-system kube-dns 
NAME       ENDPOINTS   AGE
kube-dns   <none>      63m


Finally, we have our culprit.


If we dig a little deeper, we will it is using wrong labels and selector:


student-node ~ ➜  kubectl describe svc -n kube-system kube-dns 
Name:              kube-dns
Namespace:         kube-system
....
Selector:          k8s-app=core-dns
Type:              ClusterIP
...

student-node ~ ➜  kubectl get deploy -n kube-system --show-labels | grep coredns
coredns   2/2     2            2           66m   k8s-app=kube-dns

Let's update the kube-dns service it to point to correct set of pods:


student-node ~ ➜  kubectl patch service -n kube-system kube-dns -p '{"spec":{"selector":{"k8s-app": "kube-dns"}}}'
service/kube-dns patched

student-node ~ ➜  kubectl get ep -n kube-system kube-dns 
NAME       ENDPOINTS                                              AGE
kube-dns   10.50.0.2:53,10.50.192.1:53,10.50.0.2:53 + 3 more...   69m



NOTE: We can use any method to update kube-dns service. In our case, we have used kubectl patch command.




Now let's store the correct output to /root/dns-output-12345-cka10-svcn:


student-node ~ ➜  kubectl exec -n ns-12345-svcn -i -t $POD_NAME -- nslookup kubernetes.default
Server:         10.96.0.10
Address:        10.96.0.10#53

Name:   kubernetes.default.svc.cluster.local
Address: 10.96.0.1


student-node ~ ➜  kubectl exec -n ns-12345-svcn -i -t $POD_NAME -- nslookup kubernetes.default > /root/dns-output-12345-cka10-svcn

SECTION: SERVICE NETWORKING


For this question, please set the context to cluster1 by running:


kubectl config use-context cluster1


Create a pod with name tester-cka02-svcn in dev-cka02-svcn namespace with image registry.k8s.io/e2e-test-images/jessie-dnsutils:1.3. Make sure to use command sleep 3600 with restart policy set to Always .


Once the tester-cka02-svcn pod is running, store the output of the command nslookup kubernetes.default from tester pod into the file /root/dns_output on student-node.

Change to the cluster1 context before attempting the task:

kubectl config use-context cluster1



Since the "dev-cka02-svcn" namespace doesn't exist, let's create it first:


kubectl create ns dev-cka02-svcn



Create the pod as per the requirements:


kubectl apply -f - << EOF
apiVersion: v1
kind: Pod
metadata:
  name: tester-cka02-svcn
  namespace: dev-cka02-svcn
spec:
  containers:
  - name: tester-cka02-svcn
    image: registry.k8s.io/e2e-test-images/jessie-dnsutils:1.3
    command:
      - sleep
      - "3600"
  restartPolicy: Always
EOF

Now let's test if the nslookup command is working :

student-node ~ ➜  kubectl exec -n dev-cka02-svcn -i -t tester-cka02-svcn -- nslookup kubernetes.default
;; connection timed out; no servers could be reached

command terminated with exit code 1

Looks like something is broken at the moment, if we observe the kube-system namespace, we will see no coredns pods are not running which is creating the problem, let's scale them for the nslookup command to work:

kubectl scale deployment -n kube-system coredns --replicas=2

Now let store the correct output into the /root/dns_output on student-node :

kubectl exec -n dev-cka02-svcn -i -t tester-cka02-svcn -- nslookup kubernetes.default >> /root/dns_output

We should have something similar to below output:



student-node ~ ➜  cat /root/dns_output
Server:         10.96.0.10
Address:        10.96.0.10#53

Name:   kubernetes.default.svc.cluster.local
Address: 10.96.0.1

SECTION: SERVICE NETWORKING


For this question, please set the context to cluster3 by running:


kubectl config use-context cluster3


Part I:



Create a ClusterIP service .i.e. service-3421-svcn in the spectra-1267 ns which should expose the pods namely pod-23 and pod-21 with port set to 8080 and targetport to 80.



Part II:



Store the pod names and their ip addresses from the spectra-1267 ns at /root/pod_ips_cka05_svcn where the output is sorted by their IP's.

Please ensure the format as shown below:



POD_NAME        IP_ADDR
pod-1           ip-1
pod-3           ip-2
pod-2           ip-3
...

Switching to cluster3:



kubectl config use-context cluster3



The easiest way to route traffic to a specific pod is by the use of labels and selectors . List the pods along with their labels:


student-node ~ ➜  kubectl get pods --show-labels -n spectra-1267
NAME     READY   STATUS    RESTARTS   AGE     LABELS
pod-12   1/1     Running   0          5m21s   env=dev,mode=standard,type=external
pod-34   1/1     Running   0          5m20s   env=dev,mode=standard,type=internal
pod-43   1/1     Running   0          5m20s   env=prod,mode=exam,type=internal
pod-23   1/1     Running   0          5m21s   env=dev,mode=exam,type=external
pod-32   1/1     Running   0          5m20s   env=prod,mode=standard,type=internal
pod-21   1/1     Running   0          5m20s   env=prod,mode=exam,type=external

Looks like there are a lot of pods created to confuse us. But we are only concerned with the labels of pod-23 and pod-21.



As we can see both the required pods have labels mode=exam,type=external in common. Let's confirm that using kubectl too:


student-node ~ ➜  kubectl get pod -l mode=exam,type=external -n spectra-1267                                    
NAME     READY   STATUS    RESTARTS   AGE
pod-23   1/1     Running   0          9m18s
pod-21   1/1     Running   0          9m17s


Nice!! Now as we have figured out the labels, we can proceed further with the creation of the service:

student-node ~ ➜  kubectl create service clusterip service-3421-svcn -n spectra-1267 --tcp=8080:80 --dry-run=client -o yaml > service-3421-svcn.yaml


Now modify the service definition with selectors as required before applying to k8s cluster:


student-node ~ ➜  cat service-3421-svcn.yaml 
apiVersion: v1
kind: Service
metadata:
  creationTimestamp: null
  labels:
    app: service-3421-svcn
  name: service-3421-svcn
  namespace: spectra-1267
spec:
  ports:
  - name: 8080-80
    port: 8080
    protocol: TCP
    targetPort: 80
  selector:
    app: service-3421-svcn  # delete 
    mode: exam    # add
    type: external  # add
  type: ClusterIP
status:
  loadBalancer: {}
  

Finally let's apply the service definition:


student-node ~ ➜  kubectl apply -f service-3421-svcn.yaml
service/service-3421 created

student-node ~ ➜  k get ep service-3421-svcn -n spectra-1267
NAME           ENDPOINTS                     AGE
service-3421   10.42.0.15:80,10.42.0.17:80   52s

To store all the pod name along with their IP's , we could use imperative command as shown below:


student-node ~ ➜  kubectl get pods -n spectra-1267 -o=custom-columns='POD_NAME:metadata.name,IP_ADDR:status.podIP' --sort-by=.status.podIP

POD_NAME   IP_ADDR
pod-12     10.42.0.18
pod-23     10.42.0.19
pod-34     10.42.0.20
pod-21     10.42.0.21
...

# store the output to /root/pod_ips
student-node ~ ➜  kubectl get pods -n spectra-1267 -o=custom-columns='POD_NAME:metadata.name,IP_ADDR:status.podIP' --sort-by=.status.podIP > /root/pod_ips_cka05_svcn


---

kubectl create clusterrole deploy-role-cka20-arch --verb=get --resource=deployments
 
 kubectl create clusterrolebinding deploy-role-binding-cka20-arch --clusterrole=deploy-role-cka20-arch --serviceaccount=default:deploy-cka20-arch
 
 env:
        - name: DB_ROOT_PASSWORD
          valueFrom:
            secretKeyRef:
              key: password
              name: db-root-pass-cka05-trb
        - name: DB_DATABASE
          valueFrom:
            secretKeyRef:
              key: db
              name: db-cka05-trb
        - name: DB_USER
          valueFrom:
            secretKeyRef:
              key: db-user
              name: db-user-cka05-trb
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              key: db-password
              name: db-user-pass-cka05-trb
              
              
For this question, please set the context to cluster1 by running:


kubectl config use-context cluster1


The db-deployment-cka05-trb deployment is having 0 out of 1 PODs ready.



Figure out the issues and fix the same but make sure that you do not remove any DB related environment variables from the deployment/pod.

DB deployment is fixed?

echo 'a29kZWtsb3VkX3RpbQ==' | base64 --decode

student-node ~ ➜  kubectl get secret
NAME                     TYPE     DATA   AGE
db-cka05-trb             Opaque   1      12m
db-root-pass-cka05-trb   Opaque   1      12m
db-user-pass-cka05-trb   Opaque   2      12m


password: WWNoWkhSY0xrTA==
  username: a29kZWtsb3VkX3RpbQ==
  
kubectl create secret generic db-user-cka05-trb --from-literal=db-user=kodekloud_tim



- effect: NoSchedule
    key: node
    operator: Equal
    value: cluster2-node01
    
Taints:             node=node01:NoSchedule


  kubectl set image deployment/frontend-wl04 webapp-color=webapp-color:v2
  
  
  
  kubernetes.io/hostname=cluster1-controlplane
  
  kubectl expose pod messaging-cka07-svcn --port=6379 --name=messaging-service-cka07-svcn
  
  
  kubectl get event --field-selector involvedObject.name=red-probe-cka12-trb




# SECTION: ARCHITECTURE, INSTALL AND MAINTENANCE
# Find the node across all clusters that consumes the most CPU and store the result to the file /opt/high_cpu_node in the following format cluster_name,node_name.
# The node could be in any clusters that are currently configured on the student-node.

# NOTE: It's recommended to wait for a few minutes to allow deployed objects to become fully operational and start consuming resources.


student-node ~ ➜  kubectl top node --context cluster1 --no-headers | sort -nr -k2 | head -1
cluster1-controlplane   127m   1%    703Mi   1%    

student-node ~ ➜  kubectl top node --context cluster2 --no-headers | sort -nr -k2 | head -1
cluster2-controlplane   126m   1%    675Mi   1%    

student-node ~ ➜  kubectl top node --context cluster3 --no-headers | sort -nr -k2 | head -1
cluster3-controlplane   577m   7%    1081Mi   1%    

student-node ~ ➜  kubectl top node --context cluster4 --no-headers | sort -nr -k2 | head -1
cluster4-controlplane   130m   1%    679Mi   1%    

student-node ~ ➜  

student-node ~ ➜  

# Using this, find the node that uses most cpu. In this case, it is cluster3-controlplane on cluster3.
# Save the result in the correct format to the file:
student-node ~ ➜  echo cluster3,cluster3-controlplane > /opt/high_cpu_node


# SECTION: TROUBLESHOOTING
# For this question, please set the context to cluster1 by running:

kubectl config use-context cluster1

# The blue-dp-cka09-trb deployment is having 0 out of 1 pods running. Fix the issue to make sure that pod is up and running.

# Solution
List the pods
kubectl get pod
# Most probably you see Init:Error or Init:CrashLoopBackOff for the corresponding pod.
#Look into the logs
kubectl logs blue-dp-cka09-trb-xxxx -c init-container
# You will see an error something like
# sh: can't open 'echo 'Welcome!'': No such file or directory
# Edit the deployment
kubectl edit deploy blue-dp-cka09-trb
# Under initContainers: -> - command: add -c to the next line of - sh, so final command should look like this
initContainers:
   - command:
     - sh
     - -c
     - echo 'Welcome!'

# If you will check pod then it must be failing again but with different error this time, let's find that out

kubectl get event --field-selector involvedObject.name=blue-dp-cka09-trb-xxxxx

# You will see an error something like

Warning   Failed      pod/blue-dp-cka09-trb-69dd844f76-rv9z8   Error: failed to create containerd task: failed to create shim task: OCI runtime create failed: runc create failed: unable to start container process: error during container init: error mounting "/var/lib/kubelet/pods/98182a41-6d6d-406a-a3e2-37c33036acac/volumes/kubernetes.io~configmap/nginx-config" to rootfs at "/etc/nginx/nginx.conf": mount /var/lib/kubelet/pods/98182a41-6d6d-406a-a3e2-37c33036acac/volumes/kubernetes.io~configmap/nginx-config:/etc/nginx/nginx.conf (via /proc/self/fd/6), flags: 0x5001: not a directory: unknown

# Edit the deployment again
kubectl edit deploy blue-dp-cka09-trb

# Under volumeMounts: -> - mountPath: /etc/nginx/nginx.conf -> name: nginx-config add subPath: nginx.conf and save the changes.
Finally the pod should be in running state.


# SECTION: TROUBLESHOOTING
# Question
# For this question, please set the context to cluster1 by running:
kubectl config use-context cluster1

# The purple-app-cka27-trb pod is an nginx based app on the container port 80. This app is exposed within the cluster using a ClusterIP type service called purple-svc-cka27-trb.
# There is another pod called purple-curl-cka27-trb which continuously monitors the status of the app running within purple-app-cka27-trb pod by accessing the purple-svc-cka27-trb service using curl.
# Recently we started seeing some errors in the logs of the purple-curl-cka27-trb pod.
# Dig into the logs to identify the issue and make sure it is resolved.
# Note: You will not be able to access this app directly from the student-node but you can exec into the purple-app-cka27-trb pod to check.
# Check the purple-curl-cka27-trb pod logs

kubectl logs purple-curl-cka27-trb
# You will see some logs as below
# Not able to connect to the nginx app on http://purple-svc-cka27-trb
# Now to debug let's try to access this app from within the purple-app-cka27-trb pod

kubectl exec -it purple-app-cka27-trb -- bash
curl http://purple-svc-cka27-trb
exit
# You will notice its stuck, so app is not reachable. Let's look into the service to see its configured correctly.
kubectl edit svc purple-svc-cka27-trb
# Under ports: -> port: and targetPort: is set to 8080 but nginx default port is 80 so change 8080 to 80 and save the changes
# Let's check the logs now
kubectl logs purple-curl-cka27-trb
# You will see Thank you for using nginx. in the output now.

# Question
# For this question, please set the context to cluster1 by running:
kubectl config use-context cluster1
# A template to create a Kubernetes pod is stored at /root/red-probe-cka12-trb.yaml on the student-node. However, using this template as-is is resulting in an error.


Fix the issue with this template and use it to create the pod. Once created, watch the pod for a minute or two to make sure its stable i.e, it's not crashing or restarting.


Make sure you do not update the args: section of the template.

Try to apply the template
kubectl apply -f red-probe-cka12-trb.yaml 

You will see error:
error: error validating "red-probe-cka12-trb.yaml": error validating data: [ValidationError(Pod.spec.containers[0].livenessProbe.httpGet): unknown field "command" in io.k8s.api.core.v1.HTTPGetAction, ValidationError(Pod.spec.containers[0].livenessProbe.httpGet): missing required field "port" in io.k8s.api.core.v1.HTTPGetAction]; if you choose to ignore these errors, turn validation off with --validate=false
From the error you can see that the error is for liveness probe, so let's open the template to find out:

vi red-probe-cka12-trb.yaml

Under livenessProbe: you will see the type is httpGet however the rest of the options are command based so this probe should be of exec type.

Change httpGet to exec

Try to apply the template now
kubectl apply -f red-probe-cka12-trb.yaml 

Cool it worked, now let's watch the POD status, after few seconds you will notice that POD is restarting. So let's check the logs/events
kubectl get event --field-selector involvedObject.name=red-probe-cka12-trb
You will see an error like:
21s         Warning   Unhealthy   pod/red-probe-cka12-trb   Liveness probe failed: cat: can't open '/healthcheck': No such file or directory

So seems like Liveness probe is failing, lets look into it:
vi red-probe-cka12-trb.yaml

Notice the command - sleep 3 ; touch /healthcheck; sleep 30;sleep 30000 it starts with a delay of 3 seconds, but the liveness probe initialDelaySeconds is set to 1 and failureThreshold is also 1. Which means the POD will fail just after first attempt of liveness check which will happen just after 1 second of pod start. So to make it stable we must increase the initialDelaySeconds to at least 5

vi red-probe-cka12-trb.yaml

Change initialDelaySeconds from 1 to 5 and save apply the changes.
Delete old pod:

kubectl delete pod red-probe-cka12-trb

Apply changes:

kubectl apply -f red-probe-cka12-trb.yaml

SECTION: TROUBLESHOOTING


For this question, please set the context to cluster1 by running:


kubectl config use-context cluster1


The db-deployment-cka05-trb deployment is having 0 out of 1 PODs ready.


Figure out the issues and fix the same but make sure that you do not remove any DB related environment variables from the deployment/pod.

Find out the name of the DB POD:
kubectl get pod
Check the DB POD logs:
kubectl logs <pod-name>
You might see something like as below which is not that helpful:
Error from server (BadRequest): container "db" in pod "db-deployment-cka05-trb-7457c469b7-zbvx6" is waiting to start: CreateContainerConfigError


So let's look into the kubernetes events for this pod:

kubectl get event --field-selector involvedObject.name=<pod-name>

You will see some errors as below:

Error: couldn't find key db in Secret default/db-cka05-trb


Now let's look into all secrets:

kubectl get secrets db-root-pass-cka05-trb -o yaml
kubectl get secrets db-user-pass-cka05-trb -o yaml
kubectl get secrets db-cka05-trb -o yaml

Now let's look into the deployment.

Edit the deployment

kubectl edit deployment db-deployment-cka05-trb -o yaml

You will notice that some of the keys are different what are reffered in the deployment.

Change some env keys: db to database , db-user to username and db-password to password
Change a secret reference: db-user-cka05-trb to db-user-pass-cka05-trb
Finally save the changes.


SECTION: STORAGE


For this question, please set the context to cluster1 by running:


kubectl config use-context cluster1


Create a storage class with the name banana-sc-cka08-str as per the properties given below:


- Provisioner should be kubernetes.io/no-provisioner,

- Volume binding mode should be WaitForFirstConsumer.

- Volume expansion should be enabled.



Create a yaml template as below:
kind: StorageClass
apiVersion: storage.k8s.io/v1
metadata:
  name: banana-sc-cka08-str
provisioner: kubernetes.io/no-provisioner
allowVolumeExpansion: true
volumeBindingMode: WaitForFirstConsumer

Apply the template:
kubectl apply -f <template-file-name>.yaml


# SECTION: STORAGE
# For this question, please set the context to cluster1 by running:
kubectl config use-context cluster1

# Create a storage class called orange-stc-cka07-str as per the properties given below:
- Provisioner should be kubernetes.io/no-provisioner.
- Volume binding mode should be WaitForFirstConsumer.
# Next, create a persistent volume called orange-pv-cka07-str as per the properties given below:
- Capacity should be 150Mi.
- Access mode should be ReadWriteOnce.
- Reclaim policy should be Retain.
- It should use storage class orange-stc-cka07-str.
- Local path should be /opt/orange-data-cka07-str.
- Also add node affinity to create this value on cluster1-controlplane.
# Finally, create a persistent volume claim called orange-pvc-cka07-str as per the properties given below:
- Access mode should be ReadWriteOnce.
- It should use storage class orange-stc-cka07-str.
- Storage request should be 128Mi.
- The volume should be orange-pv-cka07-str.
Create a yaml file as below:
kind: StorageClass
apiVersion: storage.k8s.io/v1
metadata:
  name: orange-stc-cka07-str
provisioner: kubernetes.io/no-provisioner
volumeBindingMode: WaitForFirstConsumer

---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: orange-pv-cka07-str
spec:
  capacity:
    storage: 150Mi
  accessModes:
  - ReadWriteOnce
  persistentVolumeReclaimPolicy: Retain
  storageClassName: orange-stc-cka07-str
  local:
    path: /opt/orange-data-cka07-str
  nodeAffinity:
    required:
      nodeSelectorTerms:
      - matchExpressions:
        - key: kubernetes.io/hostname
          operator: In
          values:
          - cluster1-controlplane

---
kind: PersistentVolumeClaim
apiVersion: v1
metadata:
  name: orange-pvc-cka07-str
spec:
  accessModes:
  - ReadWriteOnce
  storageClassName: orange-stc-cka07-str
  volumeName: orange-pv-cka07-str
  resources:
    requests:
      storage: 128Mi
# Apply the template:
# kubectl apply -f <template-file-name>.yaml

# SECTION: SERVICE NETWORKING
# For this question, please set the context to cluster3 by running:
kubectl config use-context cluster3
# Create a ReplicaSet with name checker-cka10-svcn in ns-12345-svcn namespace with image registry.k8s.io/e2e-test-images/jessie-dnsutils:1.3.
# Make sure to specify the below specs as well:
command sleep 3600
replicas set to 2
container name: dns-image
# Once the checker pods are up and running, store the output of the command nslookup kubernetes.default from any one of the checker pod into the file /root/dns-output-12345-cka10-svcn on student-node.
Change to the cluster4 context before attempting the task:
kubectl config use-context cluster3
# Create the ReplicaSet as per the requirements:



kubectl apply -f - << EOF
---
apiVersion: v1
kind: Namespace
metadata:
  creationTimestamp: null
  name: ns-12345-svcn
spec: {}
status: {}

---
apiVersion: apps/v1
kind: ReplicaSet
metadata:
  name: checker-cka10-svcn
  namespace: ns-12345-svcn
  labels:
    app: dns
    tier: testing
spec:
  replicas: 2
  selector:
    matchLabels:
      tier: testing
  template:
    metadata:
      labels:
        tier: testing
    spec:
      containers:
      - name: dns-image
        image: registry.k8s.io/e2e-test-images/jessie-dnsutils:1.3
        command:
          - sleep
          - "3600"
EOF

# Now let's test if the nslookup command is working 


student-node ~ ➜  k get pods -n ns-12345-svcn 
NAME                       READY   STATUS    RESTARTS   AGE
checker-cka10-svcn-d2cd2   1/1     Running   0          12s
checker-cka10-svcn-qj8rc   1/1     Running   0          12s

student-node ~ ➜  POD_NAME=`k get pods -n ns-12345-svcn --no-headers | head -1 | awk '{print $1}'`

student-node ~ ➜  kubectl exec -n ns-12345-svcn -i -t $POD_NAME -- nslookup kubernetes.default;; connection timed out; no servers could be reached command terminated with exit code 1
# There seems to be a problem with the name resolution. Let's check if our coredns pods are up and if any service exists to reach them:


student-node ~ ➜  k get pods -n kube-system | grep coredns
coredns-6d4b75cb6d-cprjz                        1/1     Running   0             42m
coredns-6d4b75cb6d-fdrhv                        1/1     Running   0             42m

student-node ~ ➜  k get svc -n kube-system 
NAME       TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)                  AGE
kube-dns   ClusterIP   10.96.0.10   <none>        53/UDP,53/TCP,9153/TCP   62m


Everything looks okay here but the name resolution problem exists, let's see if the kube-dns service have any active endpoints:

student-node ~ ➜  kubectl get ep -n kube-system kube-dns 
NAME       ENDPOINTS   AGE
kube-dns   <none>      63m

Finally, we have our culprit.


If we dig a little deeper, we will it is using wrong labels and selector:

student-node ~ ➜  kubectl describe svc -n kube-system kube-dns 
Name:              kube-dns
Namespace:         kube-system
....
Selector:          k8s-app=core-dns
Type:              ClusterIP
...

student-node ~ ➜  kubectl get deploy -n kube-system --show-labels | grep coredns
coredns   2/2     2            2           66m   k8s-app=kube-dns

Let's update the kube-dns service it to point to correct set of pods:


student-node ~ ➜  kubectl patch service -n kube-system kube-dns -p '{"spec":{"selector":{"k8s-app": "kube-dns"}}}'
service/kube-dns patched

student-node ~ ➜  kubectl get ep -n kube-system kube-dns 
NAME       ENDPOINTS                                              AGE
kube-dns   10.50.0.2:53,10.50.192.1:53,10.50.0.2:53 + 3 more...   69m


# NOTE: We can use any method to update kube-dns service. In our case, we have used kubectl patch command.
# Now let's store the correct output to /root/dns-output-12345-cka10-svcn:

student-node ~ ➜  kubectl exec -n ns-12345-svcn -i -t $POD_NAME -- nslookup kubernetes.default
Server:         10.96.0.10
Address:        10.96.0.10#53

Name:   kubernetes.default.svc.cluster.local
Address: 10.96.0.1

student-node ~ ➜  kubectl exec -n ns-12345-svcn -i -t $POD_NAME -- nslookup kubernetes.default > /root/dns-output-12345-cka10-svcn

# SECTION: SERVICE NETWORKING
# For this question, please set the context to cluster1 by running:
kubectl config use-context cluster1
# Create a pod with name tester-cka02-svcn in dev-cka02-svcn namespace with image registry.k8s.io/e2e-test-images/jessie-dnsutils:1.3. Make sure to use command sleep 3600 with restart policy set to Always .
# Once the tester-cka02-svcn pod is running, store the output of the command nslookup kubernetes.default from tester pod into the file /root/dns_output on student-node.
# Change to the cluster1 context before attempting the task:
kubectl config use-context cluster1
# Since the "dev-cka02-svcn" namespace doesn't exist, let's create it first:
kubectl create ns dev-cka02-svcn
# Create the pod as per the requirements:

kubectl apply -f - << EOF
apiVersion: v1
kind: Pod
metadata:
  name: tester-cka02-svcn
  namespace: dev-cka02-svcn
spec:
  containers:
  - name: tester-cka02-svcn
    image: registry.k8s.io/e2e-test-images/jessie-dnsutils:1.3
    command:
      - sleep
      - "3600"
  restartPolicy: Always
EOF

# Now let's test if the nslookup command is working :


student-node ~ ➜  kubectl exec -n dev-cka02-svcn -i -t tester-cka02-svcn -- nslookup kubernetes.default
;; connection timed out; no servers could be reached

command terminated with exit code 1

# Looks like something is broken at the moment, if we observe the kube-system namespace, we will see no coredns pods are not running which is creating the problem, let's scale them for the nslookup command to work:
kubectl scale deployment -n kube-system coredns --replicas=2
# Now let store the correct output into the /root/dns_output on student-node :
kubectl exec -n dev-cka02-svcn -i -t tester-cka02-svcn -- nslookup kubernetes.default >> /root/dns_output

# We should have something similar to below output:

student-node ~ ➜  cat /root/dns_output
Server:         10.96.0.10
Address:        10.96.0.10#53

Name:   kubernetes.default.svc.cluster.local
Address: 10.96.0.1


# SECTION: SERVICE NETWORKING
# For this question, please set the context to cluster3 by running:
kubectl config use-context cluster3
# Part I:
# Create a ClusterIP service .i.e. service-3421-svcn in the spectra-1267 ns which should expose the pods namely pod-23 and pod-21 with port set to 8080 and targetport to 80.
# Part II:
# Store the pod names and their ip addresses from the spectra-1267 ns at /root/pod_ips_cka05_svcn where the output is sorted by their IP's.
# Please ensure the format as shown below:

POD_NAME        IP_ADDR
pod-1           ip-1
pod-3           ip-2
pod-2           ip-3
...

# Switching to cluster3:
kubectl config use-context cluster3
# The easiest way to route traffic to a specific pod is by the use of labels and selectors . List the pods along with their labels:

student-node ~ ➜  kubectl get pods --show-labels -n spectra-1267
NAME     READY   STATUS    RESTARTS   AGE     LABELS
pod-12   1/1     Running   0          5m21s   env=dev,mode=standard,type=external
pod-34   1/1     Running   0          5m20s   env=dev,mode=standard,type=internal
pod-43   1/1     Running   0          5m20s   env=prod,mode=exam,type=internal
pod-23   1/1     Running   0          5m21s   env=dev,mode=exam,type=external
pod-32   1/1     Running   0          5m20s   env=prod,mode=standard,type=internal
pod-21   1/1     Running   0          5m20s   env=prod,mode=exam,type=external

# Looks like there are a lot of pods created to confuse us.
# But we are only concerned with the labels of pod-23 and pod-21.
# As we can see both the required pods have labels mode=exam,type=external in common. Let's confirm that using kubectl too:

student-node ~ ➜  kubectl get pod -l mode=exam,type=external -n spectra-1267                                    
NAME     READY   STATUS    RESTARTS   AGE
pod-23   1/1     Running   0          9m18s
pod-21   1/1     Running   0          9m17s

# Nice!! Now as we have figured out the labels, we can proceed further with the creation of the service:
student-node ~ ➜  kubectl create service clusterip service-3421-svcn -n spectra-1267 --tcp=8080:80 --dry-run=client -o yaml > service-3421-svcn.yaml
# Now modify the service definition with selectors as required before applying to k8s cluster:
student-node ~ ➜  cat service-3421-svcn.yaml 
apiVersion: v1
kind: Service
metadata:
  creationTimestamp: null
  labels:
    app: service-3421-svcn
  name: service-3421-svcn
  namespace: spectra-1267
spec:
  ports:
  - name: 8080-80
    port: 8080
    protocol: TCP
    targetPort: 80
  selector:
    app: service-3421-svcn  # delete 
    mode: exam    # add
    type: external  # add
  type: ClusterIP
status:
  loadBalancer: {}
  
# Finally let's apply the service definition:
  
student-node ~ ➜  kubectl apply -f service-3421-svcn.yaml
service/service-3421 created

student-node ~ ➜  k get ep service-3421-svcn -n spectra-1267
NAME           ENDPOINTS                     AGE
service-3421   10.42.0.15:80,10.42.0.17:80   52s

# To store all the pod name along with their IP's , we could use imperative command as shown below:

student-node ~ ➜  kubectl get pods -n spectra-1267 -o=custom-columns='POD_NAME:metadata.name,IP_ADDR:status.podIP' --sort-by=.status.podIP

POD_NAME   IP_ADDR
pod-12     10.42.0.18
pod-23     10.42.0.19
pod-34     10.42.0.20
pod-21     10.42.0.21
...

# store the output to /root/pod_ips
student-node ~ ➜  kubectl get pods -n spectra-1267 -o=custom-columns='POD_NAME:metadata.name,IP_ADDR:status.podIP' --sort-by=.status.podIP > /root/pod_ips_cka05_svcn






apt-mark unhold kubeadm && \
apt-get update && apt-get install -y kubeadm='1.27.0-00' && \
apt-mark hold kubeadm


apt-mark unhold kubelet kubectl && \
apt-get update && apt-get install -y kubelet='1.27.0-00' kubectl='1.27.0-00' && \
apt-mark hold kubelet kubectl


ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/etcd/server.crt --key=/etc/kubernetes/pki/etcd/server.key \
  snapshot save /opt/snapshot-pre-boot.db


ETCDCTL_API=3 etcdctl --data-dir=/var/lib/etcd-from-backup snapshot restore /opt/snapshot-pre-boot.db



etcd-server ~ ➜  ps -aux | grep -i etcd
etcd         814  0.0  0.0 11218368 58332 ?      Ssl  07:20   0:47 /usr/local/bin/etcd --name etcd-server --data-dir=/var/lib/etcd-data --cert-file=/etc/etcd/pki/etcd.pem --key-file=/etc/etcd/pki/etcd-key.pem --peer-cert-file=/etc/etcd/pki/etcd.pem --peer-key-file=/etc/etcd/pki/etcd-key.pem --trusted-ca-file=/etc/etcd/pki/ca.pem --peer-trusted-ca-file=/etc/etcd/pki/ca.pem --peer-client-cert-auth --client-cert-auth --initial-advertise-peer-urls https://192.12.226.19:2380 --listen-peer-urls https://192.12.226.19:2380 --advertise-client-urls https://192.12.226.19:2379 --listen-client-urls https://192.12.226.19:2379,https://127.0.0.1:2379 --initial-cluster-token etcd-cluster-1 --initial-cluster etcd-server=https://192.12.226.19:2380 --initial-cluster-state new
root        1153  0.0  0.0  13444  1156 pts/0    S+   08:22   0:00 grep -i etcd


ETCDCTL_API=3 etcdctl --endpoints https://192.12.226.19:2379 \
  --cert=/etc/etcd/pki/etcd.pem \
  --key=/etc/etcd/pki/etcd-key.pem \
  --cacert=/etc/etcd/pki/ca.pem \
  member list



ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/etcd/server.crt --key=/etc/kubernetes/pki/etcd/server.key \
  snapshot save /opt/cluster1.db

--data-dir=/var/lib/etcd-data

ETCDCTL_API=3 etcdctl --data-dir /var/lib/etcd-data-new snapshot restore /opt/cluster2.db




ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/etcd/server.crt --key=/etc/kubernetes/pki/etcd/server.key \
  snapshot save /opt/etcd-boot-cka18-trb.db
  
  
  
  student-node ~ ✖ kubectl describe no | grep -i taints
Taints:             node-role.kubernetes.io/control-plane:NoSchedule
Taints:             <none>

app=web-app-cka06-trb


ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/etcd/server.crt --key=/etc/kubernetes/pki/etcd/server.key \
  snapshot save /opt/cluster1_backup.db
  
  
  
  
  
  ETCDCTL_API=3 etcdctl --data-dir /root/default.etcd snapshot restore /opt/cluster1_backup_to_restore.db



---
Mock 7

SECTION: ARCHITECTURE, INSTALL AND MAINTENANCE


For this question, please set the context to cluster1 by running:


kubectl config use-context cluster1

There is a sample script located at /root/service-cka25-arch.sh on the student-node.
Update this script to add a command to filter/display the targetPort only for service service-cka25-arch using jsonpath. The service has been created under the default namespace on cluster1.


Update service-cka25-arch.sh script:

student-node ~ ➜ vi service-cka25-arch.sh


Add below command in it:

kubectl --context cluster1 get service service-cka25-arch -o jsonpath='{.spec.ports[0].targetPort}'


ECTION: ARCHITECTURE, INSTALL AND MAINTENANCE


For this question, please set the context to cluster3 by running:


kubectl config use-context cluster3


A pod called elastic-app-cka02-arch is running in the default namespace. The YAML file for this pod is available at /root/elastic-app-cka02-arch.yaml on the student-node. The single application container in this pod writes logs to the file /var/log/elastic-app.log.


One of our logging mechanisms needs to read these logs to send them to an upstream logging server but we don't want to increase the read overhead for our main application container so recreate this POD with an additional sidecar container that will run along with the application container and print to the STDOUT by running the command tail -f /var/log/elastic-app.log. You can use busybox image for this sidecar container.

Recreate the pod with a new container called sidecar. Update the /root/elastic-app-cka02-arch.yaml YAML file as shown below:



apiVersion: v1
kind: Pod
metadata:
  name: elastic-app-cka02-arch
spec:
  containers:
  - name: elastic-app
    image: busybox:1.28
    args:
    - /bin/sh
    - -c
    - >
      mkdir /var/log; 
      i=0;
      while true;
      do
        echo "$(date) INFO $i" >> /var/log/elastic-app.log;
        i=$((i+1));
        sleep 1;
      done
    volumeMounts:
    - name: varlog
      mountPath: /var/log
  - name: sidecar
    image: busybox:1.28
    args: [/bin/sh, -c, 'tail -f  /var/log/elastic-app.log']
    volumeMounts:
    - name: varlog
      mountPath: /var/log
  volumes:
  - name: varlog
    emptyDir: {}
    
    
    

Next, recreate the pod:

student-node ~ ➜ kubectl replace -f /root/elastic-app-cka02-arch.yaml --force --context cluster3
pod "elastic-app-cka02-arch" deleted
pod/elastic-app-cka02-arch replaced

student-node ~ ➜ 


SECTION: TROUBLESHOOTING


For this question, please set the context to cluster1 by running:


kubectl config use-context cluster1


There is a Cronjob called orange-cron-cka10-trb which is supposed to run every two minutes (i.e 13:02, 13:04, 13:06…14:02, 14:04…and so on). This cron targets the application running inside the orange-app-cka10-trb pod to make sure the app is accessible. The application has been exposed internally as a ClusterIP service.


However, this cron is not running as per the expected schedule and is not running as intended.


Make the appropriate changes so that the cronjob runs as per the required schedule and it passes the accessibility checks every-time.


Check the cron schedule
kubectl get cronjob
Make sure the schedule for orange-cron-cka10-trb crontjob is set to */2 * * * * if not then edit it.

Also before that look for the issues why this cron is failing

kubectl logs orange-cron-cka10-trb-xxxx
You will see some error like

curl: (6) Could not resolve host: orange-app-cka10-trb
You will notice that the curl is trying to hit orange-app-cka10-trb directly but it is supposed to hit the relevant service which is orange-svc-cka10-trb so we need to fix the curl command.



Edit the cronjob
kubectl edit cronjob orange-cron-cka10-trb
Change schedule * * * * * to */2 * * * *
Change command curl orange-app-cka10-trb to curl orange-svc-cka10-trb
Wait for 2 minutes to run again this cron and it should complete now.


SECTION: TROUBLESHOOTING


For this question, please set the context to cluster1 by running:


kubectl config use-context cluster1


The purple-app-cka27-trb pod is an nginx based app on the container port 80. This app is exposed within the cluster using a ClusterIP type service called purple-svc-cka27-trb.


There is another pod called purple-curl-cka27-trb which continuously monitors the status of the app running within purple-app-cka27-trb pod by accessing the purple-svc-cka27-trb service using curl.


Recently we started seeing some errors in the logs of the purple-curl-cka27-trb pod.


Dig into the logs to identify the issue and make sure it is resolved.


Note: You will not be able to access this app directly from the student-node but you can exec into the purple-app-cka27-trb pod to check.


Solution
Check the purple-curl-cka27-trb pod logs

kubectl logs purple-curl-cka27-trb
You will see some logs as below

Not able to connect to the nginx app on http://purple-svc-cka27-trb
Now to debug let's try to access this app from within the purple-app-cka27-trb pod

kubectl exec -it purple-app-cka27-trb -- bash
curl http://purple-svc-cka27-trb
exit
You will notice its stuck, so app is not reachable. Let's look into the service to see its configured correctly.

kubectl edit svc purple-svc-cka27-trb
Under ports: -> port: and targetPort: is set to 8080 but nginx default port is 80 so change 8080 to 80 and save the changes
Let's check the logs now

kubectl logs purple-curl-cka27-trb
You will see Thank you for using nginx. in the output now.


Question
SECTION: TROUBLESHOOTING


For this question, please set the context to cluster2 by running:


kubectl config use-context cluster2


We recently deployed a DaemonSet called logs-cka26-trb under kube-system namespace in cluster2 for collecting logs from all the cluster nodes including the controlplane node. However, at this moment, the DaemonSet is not creating any pod on the controlplane node.


Troubleshoot the issue and fix it to make sure the pods are getting created on all nodes including the controlplane node.


info_outline
Solution
Check the status of DaemonSet

kubectl --context2 cluster2 get ds logs-cka26-trb -n kube-system
You will find that DESIRED CURRENT READY etc have value 2 which means there are two pods that have been created. You can check the same by listing the PODs

kubectl --context2 cluster2 get pod  -n kube-system
You can check on which nodes these are created on

kubectl --context2 cluster2 get pod <pod-name> -n kube-system -o wide
Under NODE you will find the node name, so we can see that its not scheduled on the controlplane node which is because it must be missing the reqiured tolerations. Let's edit the DaemonSet to fix the tolerations

kubectl --context2 cluster2 edit ds logs-cka26-trb -n kube-system
Under tolerations: add below given tolerations as well

- key: node-role.kubernetes.io/control-plane
  operator: Exists
  effect: NoSchedule
Wait for some time PODs should schedule on all nodes now including the controlplane node.


Question
SECTION: SERVICE NETWORKING


For this question, please set the context to cluster3 by running:


kubectl config use-context cluster3


We have an external webserver running on student-node which is exposed at port 9999. We have created a service called external-webserver-cka03-svcn that can connect to our local webserver from within the kubernetes cluster3 but at the moment it is not working as expected.



Fix the issue so that other pods within cluster3 can use external-webserver-cka03-svcn service to access the webserver.


Let's check if the webserver is working or not:


student-node ~ ➜  curl student-node:9999
...
<h1>Welcome to nginx!</h1>
...



Now we will check if service is correctly defined:


student-node ~ ➜  kubectl describe svc external-webserver-cka03-svcn 
Name:              external-webserver-cka03-svcn
Namespace:         default
.
.
Endpoints:         <none> # there are no endpoints for the service
...

As we can see there is no endpoints specified for the service, hence we won't be able to get any output. Since we can not destroy any k8s object, let's create the endpoint manually for this service as shown below:

student-node ~ ➜  export IP_ADDR=$(ifconfig eth0 | grep inet | awk '{print $2}')

student-node ~ ➜ kubectl --context cluster3 apply -f - <<EOF
apiVersion: v1
kind: Endpoints
metadata:
  # the name here should match the name of the Service
  name: external-webserver-cka03-svcn
subsets:
  - addresses:
      - ip: $IP_ADDR
    ports:
      - port: 9999
EOF

Finally check if the curl test works now:

tudent-node ~ ➜  kubectl --context cluster3 run --rm  -i test-curl-pod --image=curlimages/curl --restart=Never -- curl -m 2 external-webserver-cka03-svcn
...
<title>Welcome to nginx!</title>
...


SECTION: SERVICE NETWORKING


For this question, please set the context to cluster1 by running:


kubectl config use-context cluster1


Create a nginx pod called nginx-resolver-cka06-svcn using image nginx, expose it internally with a service called nginx-resolver-service-cka06-svcn.



Test that you are able to look up the service and pod names from within the cluster. Use the image: busybox:1.28 for dns lookup. Record results in /root/CKA/nginx.svc.cka06.svcn and /root/CKA/nginx.pod.cka06.svcn



Solution
Switching to cluster1:



kubectl config use-context cluster1



To create a pod nginx-resolver-cka06-svcn and expose it internally:


student-node ~ ➜ kubectl run nginx-resolver-cka06-svcn --image=nginx 
student-node ~ ➜ kubectl expose pod/nginx-resolver-cka06-svcn --name=nginx-resolver-service-cka06-svcn --port=80 --target-port=80 --type=ClusterIP 

To create a pod test-nslookup. Test that you are able to look up the service and pod names from within the cluster:

student-node ~ ➜  kubectl run test-nslookup --image=busybox:1.28 --rm -it --restart=Never -- nslookup nginx-resolver-service-cka06-svcn
student-node ~ ➜  kubectl run test-nslookup --image=busybox:1.28 --rm -it --restart=Never -- nslookup nginx-resolver-service-cka06-svcn > /root/CKA/nginx.svc.cka06.svcn

Get the IP of the nginx-resolver-cka06-svcn pod and replace the dots(.) with hyphon(-) which will be used below.

tudent-node ~ ➜  kubectl get pod nginx-resolver-cka06-svcn -o wide
student-node ~ ➜  IP=`kubectl get pod nginx-resolver-cka06-svcn -o wide --no-headers | awk '{print $6}' | tr '.' '-'`
student-node ~ ➜  kubectl run test-nslookup --image=busybox:1.28 --rm -it --restart=Never -- nslookup $IP.default.pod > /root/CKA/nginx.pod.cka06.svcn

SECTION: SERVICE NETWORKING


For this question, please set the context to cluster3 by running:


kubectl config use-context cluster3


Create a loadbalancer service with name wear-service-cka09-svcn to expose the deployment webapp-wear-cka09-svcn application in app-space namespace.

Switch to cluster3 :



kubectl config use-context cluster3


On student node run the command:

student-node ~ ➜  kubectl expose -n app-space deployment webapp-wear-cka09-svcn --type=LoadBalancer --name=wear-service-cka09-svcn --port=8080
service/wear-service-cka09-svcn exposed

student-node ~ ➜  k get svc -n app-space
NAME                      TYPE           CLUSTER-IP     EXTERNAL-IP   PORT(S)          AGE
wear-service-cka09-svcn   LoadBalancer   10.43.68.233   172.25.0.14   8080:32109/TCP   14s


Question
SECTION: SERVICE NETWORKING


For this question, please set the context to cluster3 by running:


kubectl config use-context cluster3


Part I:



Create a ClusterIP service .i.e. service-3421-svcn in the spectra-1267 ns which should expose the pods namely pod-23 and pod-21 with port set to 8080 and targetport to 80.



Part II:



Store the pod names and their ip addresses from the spectra-1267 ns at /root/pod_ips_cka05_svcn where the output is sorted by their IP's.

Please ensure the format as shown below:



POD_NAME        IP_ADDR
pod-1           ip-1
pod-3           ip-2
pod-2           ip-3
...



Solution
Switching to cluster3:



kubectl config use-context cluster3



The easiest way to route traffic to a specific pod is by the use of labels and selectors . List the pods along with their labels:


student-node ~ ➜  kubectl get pods --show-labels -n spectra-1267
NAME     READY   STATUS    RESTARTS   AGE     LABELS
pod-12   1/1     Running   0          5m21s   env=dev,mode=standard,type=external
pod-34   1/1     Running   0          5m20s   env=dev,mode=standard,type=internal
pod-43   1/1     Running   0          5m20s   env=prod,mode=exam,type=internal
pod-23   1/1     Running   0          5m21s   env=dev,mode=exam,type=external
pod-32   1/1     Running   0          5m20s   env=prod,mode=standard,type=internal
pod-21   1/1     Running   0          5m20s   env=prod,mode=exam,type=external

Looks like there are a lot of pods created to confuse us. But we are only concerned with the labels of pod-23 and pod-21.



As we can see both the required pods have labels mode=exam,type=external in common. Let's confirm that using kubectl too:

student-node ~ ➜  kubectl get pod -l mode=exam,type=external -n spectra-1267                                    
NAME     READY   STATUS    RESTARTS   AGE
pod-23   1/1     Running   0          9m18s
pod-21   1/1     Running   0          9m17s


Nice!! Now as we have figured out the labels, we can proceed further with the creation of the service:


student-node ~ ➜  kubectl create service clusterip service-3421-svcn -n spectra-1267 --tcp=8080:80 --dry-run=client -o yaml > service-3421-svcn.yaml


Now modify the service definition with selectors as required before applying to k8s cluster:


student-node ~ ➜  cat service-3421-svcn.yaml 
apiVersion: v1
kind: Service
metadata:
  creationTimestamp: null
  labels:
    app: service-3421-svcn
  name: service-3421-svcn
  namespace: spectra-1267
spec:
  ports:
  - name: 8080-80
    port: 8080
    protocol: TCP
    targetPort: 80
  selector:
    app: service-3421-svcn  # delete 
    mode: exam    # add
    type: external  # add
  type: ClusterIP
status:
  loadBalancer: {}
  
  
Finally let's apply the service definition:



student-node ~ ➜  kubectl apply -f service-3421-svcn.yaml
service/service-3421 created

student-node ~ ➜  k get ep service-3421-svcn -n spectra-1267
NAME           ENDPOINTS                     AGE
service-3421   10.42.0.15:80,10.42.0.17:80   52s


To store all the pod name along with their IP's , we could use imperative command as shown below:


student-node ~ ➜  kubectl get pods -n spectra-1267 -o=custom-columns='POD_NAME:metadata.name,IP_ADDR:status.podIP' --sort-by=.status.podIP

POD_NAME   IP_ADDR
pod-12     10.42.0.18
pod-23     10.42.0.19
pod-34     10.42.0.20
pod-21     10.42.0.21
...

# store the output to /root/pod_ips
student-node ~ ➜  kubectl get pods -n spectra-1267 -o=custom-columns='POD_NAME:metadata.name,IP_ADDR:status.podIP' --sort-by=.status.podIP > /root/pod_ips_cka05_svcn









ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/etcd/server.crt --key=/etc/kubernetes/pki/etcd/server.key \
  snapshot save /opt/cluster1_backup.db
  
  


80 %


Find the node across all clusters that consumes the most memory and store the result to the file /opt/high_memory_node in the following format cluster_name,node_name.

The node could be in any clusters that are currently configured on the student-node.

Check out the metrics for all node across all clusters:

student-node ~ ➜  kubectl top node --context cluster1 --no-headers | sort -nr -k4 | head -1
cluster1-controlplane   124m   1%    768Mi   1%    

student-node ~ ➜  kubectl top node --context cluster2 --no-headers | sort -nr -k4 | head -1
cluster2-controlplane   79m   0%    873Mi   1%    

student-node ~ ➜  kubectl top node --context cluster3 --no-headers | sort -nr -k4 | head -1
cluster3-controlplane   78m   0%    902Mi   1%  

student-node ~ ➜  kubectl top node --context cluster4 --no-headers | sort -nr -k4 | head -1
cluster4-controlplane   78m   0%    901Mi   1%    



Using this, find the node that uses most memory. In this case, it is cluster3-controlplane on cluster3.
Save the result in the correct format to the file:
student-node ~ ➜  echo cluster3,cluster3-controlplane > /opt/high_memory_node 


Q. 10
info_outline
Question
SECTION: TROUBLESHOOTING


For this question, please set the context to cluster4 by running:


kubectl config use-context cluster4


There is a pod called pink-pod-cka16-trb created in the default namespace in cluster4. This app runs on port tcp/5000 and it is exposed to end-users using an ingress resource called pink-ing-cka16-trb in such a way that it is supposed to be accessible using the command: curl http://kodekloud-pink.app on cluster4-controlplane host.


However, this is not working. Troubleshoot and fix this issue, making any necessary to the objects.



Note: You should be able to ssh into the cluster4-controlplane using ssh cluster4-controlplane command.


SSH into the cluster4-controlplane host and try to access the app.
ssh cluster4-controlplane
curl kodekloud-pink.app
You must be getting 503 Service Temporarily Unavailabl error.
Let's look into the service:

kubectl edit svc pink-svc-cka16-trb
Under ports: change protocol: UDP to protocol: TCP


Try to access the app again

curl kodekloud-pink.app
You must be getting curl: (6) Could not resolve host: example.com error, from the error we can see that its not able to resolve example.com host which indicated that it can be some issue related to the DNS. As we know CoreDNS is a DNS server that can serve as the Kubernetes cluster DNS, so it can be something related to CoreDNS.

Let's check if we have CoreDNS deployment running



kubectl get deploy -n kube-system
You will see that for coredns all relicas are down, you will see 0/0 ready pods. So let's scale up this deployment.


kubectl scale --replicas=2 deployment coredns -n kube-system


Once CoreDBS is up let's try to access to app again.

curl kodekloud-pink.app
It should work now.



Q. 11
info_outline
Question
SECTION: TROUBLESHOOTING


For this question, please set the context to cluster2 by running:


kubectl config use-context cluster2


We recently deployed a DaemonSet called logs-cka26-trb under kube-system namespace in cluster2 for collecting logs from all the cluster nodes including the controlplane node. However, at this moment, the DaemonSet is not creating any pod on the controlplane node.


Troubleshoot the issue and fix it to make sure the pods are getting created on all nodes including the controlplane node.


info_outline
Solution
Check the status of DaemonSet

kubectl --context2 cluster2 get ds logs-cka26-trb -n kube-system

You will find that DESIRED CURRENT READY etc have value 2 which means there are two pods that have been created. You can check the same by listing the PODs

kubectl --context2 cluster2 get pod  -n kube-system

You can check on which nodes these are created on

kubectl --context2 cluster2 get pod <pod-name> -n kube-system -o wide

Under NODE you will find the node name, so we can see that its not scheduled on the controlplane node which is because it must be missing the reqiured tolerations. Let's edit the DaemonSet to fix the tolerations

kubectl --context2 cluster2 edit ds logs-cka26-trb -n kube-system

Under tolerations: add below given tolerations as well


- key: node-role.kubernetes.io/control-plane
  operator: Exists
  effect: NoSchedule
  
  Wait for some time PODs should schedule on all nodes now including the controlplane node.
  
Q. 17
info_outline
Question
SECTION: SERVICE NETWORKING


For this question, please set the context to cluster1 by running:


kubectl config use-context cluster1


John is setting up a two tier application stack that is supposed to be accessible using the service curlme-cka01-svcn. To test that the service is accessible, he is using a pod called curlpod-cka01-svcn. However, at the moment, he is unable to get any response from the application.



Troubleshoot and fix this issue so the application stack is accessible.



While you may delete and recreate the service curlme-cka01-svcn, please do not alter it in anyway.


Test if the service curlme-cka01-svcn is accessible from pod curlpod-cka01-svcn or not.

kubectl exec curlpod-cka01-svcn -- curl curlme-cka01-svcn

.....
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:--  0:00:10 --:--:--     0
  
  
We did not get any response. Check if the service is properly configured or not.



kubectl describe svc curlme-cka01-svcn ''

....
Name:              curlme-cka01-svcn
Namespace:         default
Labels:            <none>
Annotations:       <none>
Selector:          run=curlme-ckaO1-svcn
Type:              ClusterIP
IP Family Policy:  SingleStack
IP Families:       IPv4
IP:                10.109.45.180
IPs:               10.109.45.180
Port:              <unset>  80/TCP
TargetPort:        80/TCP
Endpoints:         <none>
Session Affinity:  None
Events:            <none>


The service has no endpoints configured. As we can delete the resource, let's delete the service and create the service again.

To delete the service, use the command kubectl delete svc curlme-cka01-svcn.
You can create the service using imperative way or declarative way.


Using imperative command:

kubectl expose pod curlme-cka01-svcn --port=80

Using declarative manifest:


apiVersion: v1
kind: Service
metadata:
  labels:
    run: curlme-cka01-svcn
  name: curlme-cka01-svcn
spec:
  ports:
  - port: 80
    protocol: TCP
    targetPort: 80
  selector:
    run: curlme-cka01-svcn
  type: ClusterIP



You can test the connection from curlpod-cka-1-svcn using following.



kubectl exec curlpod-cka01-svcn -- curl curlme-cka01-svcn


Q. 18
info_outline
Question
SECTION: SERVICE NETWORKING


For this question, please set the context to cluster3 by running:


kubectl config use-context cluster3


Create a ReplicaSet with name checker-cka10-svcn in ns-12345-svcn namespace with image registry.k8s.io/e2e-test-images/jessie-dnsutils:1.3.


Make sure to specify the below specs as well:


command sleep 3600
replicas set to 2
container name: dns-image



Once the checker pods are up and running, store the output of the command nslookup kubernetes.default from any one of the checker pod into the file /root/dns-output-12345-cka10-svcn on student-node.


info_outline
Solution
Change to the cluster4 context before attempting the task:

kubectl config use-context cluster3



Create the ReplicaSet as per the requirements:


kubectl apply -f - << EOF
---
apiVersion: v1
kind: Namespace
metadata:
  creationTimestamp: null
  name: ns-12345-svcn
spec: {}
status: {}

---
apiVersion: apps/v1
kind: ReplicaSet
metadata:
  name: checker-cka10-svcn
  namespace: ns-12345-svcn
  labels:
    app: dns
    tier: testing
spec:
  replicas: 2
  selector:
    matchLabels:
      tier: testing
  template:
    metadata:
      labels:
        tier: testing
    spec:
      containers:
      - name: dns-image
        image: registry.k8s.io/e2e-test-images/jessie-dnsutils:1.3
        command:
          - sleep
          - "3600"
EOF


Now let's test if the nslookup command is working :


student-node ~ ➜  k get pods -n ns-12345-svcn 
NAME                       READY   STATUS    RESTARTS   AGE
checker-cka10-svcn-d2cd2   1/1     Running   0          12s
checker-cka10-svcn-qj8rc   1/1     Running   0          12s

student-node ~ ➜  POD_NAME=`k get pods -n ns-12345-svcn --no-headers | head -1 | awk '{print $1}'`

student-node ~ ➜  kubectl exec -n ns-12345-svcn -i -t $POD_NAME -- nslookup kubernetes.default
;; connection timed out; no servers could be reached

command terminated with exit code 1


There seems to be a problem with the name resolution. Let's check if our coredns pods are up and if any service exists to reach them:

student-node ~ ➜  k get pods -n kube-system | grep coredns
coredns-6d4b75cb6d-cprjz                        1/1     Running   0             42m
coredns-6d4b75cb6d-fdrhv                        1/1     Running   0             42m

student-node ~ ➜  k get svc -n kube-system 
NAME       TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)                  AGE
kube-dns   ClusterIP   10.96.0.10   <none>        53/UDP,53/TCP,9153/TCP   62m


Everything looks okay here but the name resolution problem exists, let's see if the kube-dns service have any active endpoints:


student-node ~ ➜  kubectl get ep -n kube-system kube-dns 
NAME       ENDPOINTS   AGE
kube-dns   <none>      63m



Finally, we have our culprit.


If we dig a little deeper, we will it is using wrong labels and selector:



student-node ~ ➜  kubectl describe svc -n kube-system kube-dns 
Name:              kube-dns
Namespace:         kube-system
....
Selector:          k8s-app=core-dns
Type:              ClusterIP
...

student-node ~ ➜  kubectl get deploy -n kube-system --show-labels | grep coredns
coredns   2/2     2            2           66m   k8s-app=kube-dns



Let's update the kube-dns service it to point to correct set of pods:

student-node ~ ➜  kubectl patch service -n kube-system kube-dns -p '{"spec":{"selector":{"k8s-app": "kube-dns"}}}'
service/kube-dns patched

student-node ~ ➜  kubectl get ep -n kube-system kube-dns 
NAME       ENDPOINTS                                              AGE
kube-dns   10.50.0.2:53,10.50.192.1:53,10.50.0.2:53 + 3 more...   69m



NOTE: We can use any method to update kube-dns service. In our case, we have used kubectl patch command.




Now let's store the correct output to /root/dns-output-12345-cka10-svcn:



student-node ~ ➜  kubectl exec -n ns-12345-svcn -i -t $POD_NAME -- nslookup kubernetes.default
Server:         10.96.0.10
Address:        10.96.0.10#53

Name:   kubernetes.default.svc.cluster.local
Address: 10.96.0.1


student-node ~ ➜  kubectl exec -n ns-12345-svcn -i -t $POD_NAME -- nslookup kubernetes.default > /root/dns-output-12345-cka10-svcn


---

Difficult Questions

student-node ~ ➜  k get po -A --sort-by=.metadata.creationTimestamp
NAMESPACE     NAME                                            READY   STATUS             RESTARTS       AGE
kube-system   etcd-cluster1-controlplane                      1/1     Running            0              118m
kube-system   kube-apiserver-cluster1-controlplane            1/1     Running            0              118m
kube-system   kube-controller-manager-cluster1-controlplane   1/1     Running            0              118m
kube-system   kube-scheduler-cluster1-controlplane            1/1     Running            0              118m
kube-system   kube-proxy-7d75r                                1/1     Running            0              118m
kube-system   weave-net-6r9sb                                 2/2     Running            1 (118m ago)   118m
kube-system   coredns-565d847f94-64bh5                        1/1     Running            0              118m
kube-system   coredns-565d847f94-8z2xx                        1/1     Running            0              118m
kube-system   weave-net-4dqn8                                 2/2     Running            0              117m
kube-system   kube-proxy-dtkxt                                1/1     Running            0              117m
kube-system   kube-proxy-cggdz                                1/1     Running            0              117m
kube-system   weave-net-nsvzp                                 2/2     Running            0              117m
default       busybox                                         1/1     Running            0              27m
default       nginx-76d6c9b8c-tkzql                           1/1     Running            0              26m
default       nginx-76d6c9b8c-c9fbf                           1/1     Running            0              26m
default       nginx-76d6c9b8c-nld2v                           1/1     Running            0              26m
default       httpd-65bfffd87f-tnfvp                          1/1     Running            0              25m
default       httpd-65bfffd87f-s6zm5                          1/1     Running            0              25m
default       httpd-65bfffd87f-pdrth                          1/1     Running            0              25m
default       mysql-68f7776797-xlcbv                          0/1     CrashLoopBackOff   7 (98s ago)    12m

student-node ~ ✖ k get po -A --sort-by=.metadata.creationTimestamp | tac
default       mysql-68f7776797-xlcbv                          0/1     CrashLoopBackOff   7 (3m16s ago)   14m
default       httpd-65bfffd87f-pdrth                          1/1     Running            0               27m
default       httpd-65bfffd87f-s6zm5                          1/1     Running            0               27m
default       httpd-65bfffd87f-tnfvp                          1/1     Running            0               27m
default       nginx-76d6c9b8c-nld2v                           1/1     Running            0               27m
default       nginx-76d6c9b8c-c9fbf                           1/1     Running            0               27m
default       nginx-76d6c9b8c-tkzql                           1/1     Running            0               27m
default       busybox                                         1/1     Running            0               29m
kube-system   weave-net-nsvzp                                 2/2     Running            0               119m
kube-system   kube-proxy-cggdz                                1/1     Running            0               119m
kube-system   kube-proxy-dtkxt                                1/1     Running            0               119m
kube-system   weave-net-4dqn8                                 2/2     Running            0               119m
kube-system   coredns-565d847f94-8z2xx                        1/1     Running            0               119m
kube-system   coredns-565d847f94-64bh5                        1/1     Running            0               119m
kube-system   weave-net-6r9sb                                 2/2     Running            1 (119m ago)    119m
kube-system   kube-proxy-7d75r                                1/1     Running            0               119m
kube-system   kube-scheduler-cluster1-controlplane            1/1     Running            0               120m
kube-system   kube-controller-manager-cluster1-controlplane   1/1     Running            0               120m
kube-system   kube-apiserver-cluster1-controlplane            1/1     Running            0               120m
kube-system   etcd-cluster1-controlplane                      1/1     Running            0               120m
NAMESPACE     NAME                                            READY   STATUS             RESTARTS        AGE


student-node ~ ➜  kubectl get nodes -o jsonpath='{.items[*].status.addresses[?(@.type=="InternalIP")].address}'
192.4.82.10 192.4.82.6 192.4.82.3


---



