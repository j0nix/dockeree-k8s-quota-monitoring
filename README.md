# dockeree-k8s-quota-monitoring
To calculate and visualize utilization of resource quotas in a Kubernetes cluster.  

![grafana-dashboard](grafana.png)

## How it works
* Sums up worker nodes cpu & memory resources. 
* Sums all namespace resource quota limits.
* Fetches namespace quota limits and current resource reservations.  

Calculates cluster and namespace utilization before sending the result as json to Elasticsearch.   

## Requirements
* A DockerEE kubernetes cluster (obviously) to deploy app
* A Elasticsearch installation to send results to
* Grafana for presentation (**optional**)

## HowTo
Requires the following environment variables to be set
> DOCKEREE_USERNAME 
> DOCKEREE_PASSWORD 
> DOCKEREE_HOST 
> ELASTIC_USERNAME
> ELASTIC_PASSWORD
> ELASTIC_HOST 
> ELASTIC_PORT
 
 Preferably with kubernetes secrets. Review `k8s/k8s_exaxmple.yaml` for example. 
 
 Setup your elasticsearch, if not require auth you just set `DOCKEREE_USERNAME`and `DOCKEREE_PASSWORD`as `null`.

Build and deploy in your DockerEE k8s cluster

