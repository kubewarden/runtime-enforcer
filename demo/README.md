# Commands

```bash
kind create cluster
tilt up

kubectl apply -f ./runtime-enforcer/demo/ubuntu.yaml
kubectl exec -it deployments/ubuntu -- bash
# should show learning events...

# add a new container
kubectl debug ... -it --profile=sysadmin -c andrea-debugger --image=ubuntu:latest

#############
# deploy a policy
#############
kubectl apply -f ./runtime-enforcer/demo/wp.yaml
sudo bpftool map show | grep cg_to_policy_ma
sudo bpftool map dump id 78

sudo bpftool map show | grep p_1_str_map_0
sudo bpftool map dump id 341

#############
# deploy a policy
#############
kubectl patch workloadsecuritypolicy deploy-ubuntu -n default --type='json' -p='[{"op": "replace", "path": "/spec/mode", "value": "protect"}]'


kubectl delete -f ./runtime-enforcer/demo/ubuntu.yaml
kubectl delete -f ./runtime-enforcer/demo/wp.yaml
```
