#!/bin/bash

usage() {
cat << EOF
usage: helm ops_sanity_check <COMMAND> <SUB_COMMAND>
Available Commands:
    pre-check                 Perform Pre-checks
    post-check                Perform Post-checks
    --help                    Display this text
    --cleanup                 To explicitly run the cleanup. Default action
Available Sub-Commands:
    --disable-cleanup         To disable cleanup
EOF
}

# Variables declaration
chk_cond="$1"
cln_cond="$2"
sleep_sec=5
pod_retry_count=10
oc_pod_name="oc-net-utils-$(tr -dc a-z0-9 </dev/urandom | head -c 5)"
OC_NAMESPACE="oc-sanity-check"
REDHAT="false"
declare -a OC_SOUTH_NAMESPACES=("opscruise" "collectors")
declare -a repos=("https://grafana.github.io/helm-charts/" "https://jaegertracing.github.io/helm-charts/" \
"https://prometheus-community.github.io/helm-charts/" "https://hub.docker.com/" \
"https://console.cloud.google.com/gcr/images/google-containers/GLOBAL/" "https://quay.io/repository/")
declare -a lnx_distro=("ubuntu" "amzn" "centos")
declare -a ubuntu_kernel_loc=("security.ubuntu.com:80")
declare -a centos_kernel_loc=("download.cf.centos.org:443" "mirror.centos.org:80")
if [ -f 'opscruise-values.yaml' ]; then
  aws_region=$(cat opscruise-values.yaml | grep region | head -1 | awk -F': ' '{print $2}' | sed s/[\"]//g)
else
  aws_region="us-east-1"
fi
declare -a amzn_kernel_loc=("amazonlinux-2-repos-${aws_region}.s3.dualstack.${aws_region}.amazonaws.com:443:80" "amazonlinux-2-repos-${aws_region}.s3.${aws_region}.amazonaws.com:443")
OC_DOCKER_SECRET_NAME="oc-docker-netutils"
if [ -f 'opscruise-values.yaml' ]; then
  OC_DOCKER_SECRET_USERNAME=$(cat opscruise-values.yaml | grep DOCKER_USERNAME | awk -F': ' '{print $2}' | sed s/[\"]//g)
  OC_DOCKER_SECRET_PASSWORD=$(cat opscruise-values.yaml | grep DOCKER_PASSWORD | awk -F': ' '{print $2}' | sed s/[\"]//g)
  OC_DOCKER_SECRET_EMAIL=$(cat opscruise-values.yaml | grep DOCKER_EMAIL | awk -F': ' '{print $2}' | sed s/[\"]//g)
else
  echo "File \"opscruise-values.yaml\" does not exist under the path \"$(pwd)\". Aborting execution..."
  exit 1
fi

# Cleanup function
cleanup() {
  if [ "$cln_cond" == "--disable-cleanup" ]; then
    echo "Cleanup is disabled..."
  else
    echo "Cleaning up..."
    if $(kubectl get pod ${oc_pod_name} -n ${OC_NAMESPACE} &> /dev/null); then
      kubectl delete pod ${oc_pod_name} -n ${OC_NAMESPACE}
    fi
    if $(kubectl get secret ${OC_DOCKER_SECRET_NAME} -n ${OC_NAMESPACE} &> /dev/null); then
      kubectl delete secret ${OC_DOCKER_SECRET_NAME} -n ${OC_NAMESPACE}
    fi
    if [ -f ./oc-net.yaml ]; then
      rm -v oc-net.yaml
    fi
    if [ -f ./kernel_check.sh ]; then
      rm -v kernel_check.sh
    fi
    ns_op=$(kubectl get all -n ${OC_NAMESPACE} 2>&1)
    kubectl delete ns ${OC_NAMESPACE} 2> /dev/null
  fi
}

trap 'cleanup' EXIT


sanity_check_pod() {
  echo -e "\t--> Creating a test Pod to check connectivity"
  count=0
  kubectl create ns ${OC_NAMESPACE} > /dev/null && \
  echo -e "[ ${BGREEN}OK${NC} ] ... Created namespace \"${OC_NAMESPACE}\"" || \
  echo -e "[ ${BRED}FAILED${NC} ] ... Unable to create namespace \"${OC_NAMESPACE}\""
  kubectl create secret docker-registry ${OC_DOCKER_SECRET_NAME} \
  --docker-server=https://index.docker.io/v1/ \
  --docker-username="${OC_DOCKER_SECRET_USERNAME}" \
  --docker-password="${OC_DOCKER_SECRET_PASSWORD}" \
  --docker-email="${OC_DOCKER_SECRET_EMAIL}" -n ${OC_NAMESPACE} > /dev/null && \
  echo -e "[ ${BGREEN}OK${NC} ] ... Opscruise docker secret created" || \
  echo -e "[ ${BRED}FAILED${NC} ] ... Unable to created Opscruise docker secret"
  cat << EOF > ./oc-net.yaml
---
apiVersion: v1
kind: Pod
metadata:
  name: ${oc_pod_name}
  namespace: ${OC_NAMESPACE}
spec:
  containers:
  - name: net-util
    image: opscruiseindia/oc-net-utils:v1.2
    imagePullPolicy: Always
    volumeMounts:
    - name: src
      mountPath: /usr/src
      readOnly: true
    - name: osrel
      mountPath: /etc/os-release
      readOnly: true
  imagePullSecrets:
  - name: ${OC_DOCKER_SECRET_NAME}
  volumes:
  - hostPath:
      path: /etc/os-release
    name: osrel
  - hostPath:
      path: /usr/src
    name: src
EOF
  if op=$(kubectl apply -f ./oc-net.yaml); then
    echo -e "[ ${BGREEN}OK${NC} ] ... $op"
    while [ "$count" -lt "$pod_retry_count" ]; do
      pod_status=$(kubectl get pod ${oc_pod_name} -n ${OC_NAMESPACE} -o jsonpath='{.status.containerStatuses[*].started}')
      if [ "$pod_status" == "true" ]; then
        echo "Pod started"
        sleep $sleep_sec
        break
      else
        echo "waiting for the pod to start... Sleep "$sleep_sec"s"
        count=$(( count + 1 ))
        sleep $sleep_sec
      fi
    done
    if [ "$pod_status" != "true" ]; then
      duration=$(( count * 5 ))
      echo -e "[ ${BRED}FAILED${NC} ] ... Pod is not started in the given duratiuon ${duration}s. Hence aborting execution."
      err_count=$(( err_count + 1 ))
      echo
      echo "Status: \"$err_count\" error(s) found in Pre-check."
      echo
      exit 1
    fi
    echo
  else
    echo -e "[ ${BRED}FAILED${NC} ] ... Unable to create test Pod. Hence aborting execution."
    err_count=$(( err_count + 1 ))
    echo
    echo "Status: \"$err_count\" error(s) found in Pre-check."
    echo
    exit 1
  fi
}


pre-requisite() {
  err_count=0
  doc_chk=0
  echo "--------------------------------------------------------"
  echo "-------------- Checking Pre-requisites -----------------"
  echo "--------------------------------------------------------"
  kubectl version --client=true --short=true &> /dev/null
  if [ $? -gt 0 ]; then
    echo -e "[ ${BRED}FAILED${NC} ] ... Kubectl package is not present"
    err_count=$(( err_count + 1 ))
  else
    echo -e "[ ${BGREEN}OK${NC} ] ... Kubectl package is present"
  fi
  kubectl get nodes &> /dev/null
  if [ $? -gt 0 ]; then
    echo -e "[ ${BRED}FAILED${NC} ] ... K8s cluster is not accessible"
    err_count=$(( err_count + 1 ))
  else
    echo -e "[ ${BGREEN}OK${NC} ] ... K8s cluster is accessible"
  fi
  helm version --short &> /dev/null
  if [ $? -gt 0 ]; then
    echo -e "[ ${BRED}FAILED${NC} ] ... HELM package is not present"
    err_count=$(( err_count + 1 ))
  else
    echo -e "[ ${BGREEN}OK${NC} ] ... HELM package is present"
  fi
  echo
  if [ "$err_count" -gt 0 ]; then
    echo "Status: \"$err_count\" error(s) found in Pre-requisite check. Aborting execution and not initiating Pre-check."
    echo
    exit 1
  else
    echo -e "\tPre-requisite check is successful. Initiating Pre-check..."
    echo
  fi
}

pre-check() {
  err_count=0
  doc_hub=0
  echo "--------------------------------------------------------"
  echo "----------------- Running Pre-checks -------------------"
  echo "--------------------------------------------------------"
  echo
  echo -e "\t--> OS and Kernel Version of Nodes in the Cluster"
  op=$(kubectl get nodes -o custom-columns=Node_Name:.metadata.name,OS_Name:.status.nodeInfo.osImage,Kernel_version:.status.nodeInfo.kernelVersion)
  if [ $? -eq 0 ]; then
    echo "$op"
    os_chk=$(kubectl get nodes -o custom-columns=OS_Name:.status.nodeInfo.osImage | awk 'NR==2')
    if [[ "$os_chk" == *"Red Hat"* ]]; then
      REDHAT="true"
    fi
  else
    echo -e "[ ${BRED}FAILED${NC} ] ... Unable to fetch node details"
    err_count=$(( err_count + 1 ))
  fi
  echo
  echo -e "\t--> Kubernetes Cluster Version"
  op=$(kubectl version --short=true | grep Server)
  if [ $? -eq 0 ]; then
    echo "$op" | sed s/Server/Kubernetes/g
  else
    echo -e "[ ${BRED}FAILED${NC} ] ... Unable to get cluster version"
    err_count=$(( err_count + 1 ))
  fi
  echo
  echo -e "\t--> EKS/AKS/GKE Version"
  k8s_ver=$(kubectl version --short=true | grep Server)
  k8s_node=$(kubectl get nodes --no-headers -o jsonpath='{.items[0].metadata.name}')
  k8s_cluster_ver=$(kubectl get nodes --no-headers -o jsonpath='{.items[0].status.nodeInfo.kubeletVersion}')
  if [[ "$k8s_ver" == *"eks"* && "$k8s_node" == *"ec2"* ]]; then
    echo "AWS EKS Cluster Version : ${k8s_cluster_ver}"
  elif [[ "$k8s_ver" == *"gke"* && "$k8s_node" == *"gke"* ]]; then
    echo "GoogleCloud GKE Cluster Version : ${k8s_cluster_ver}"
  elif [[ "$k8s_node" == *"aks"* ]]; then
    echo "Azure AKS Cluster Version : ${k8s_cluster_ver}"
  else
    echo "Cluster is not running in EKS/AKS/GKE"
  fi
  echo
  echo -e "\t--> Checking connectivity to DockerHub - Opscruise Image Repository"
  http_code=$(curl -n -s -o /dev/null -w "%{http_code}" --max-time 15 https://hub.docker.com/orgs/opscruiseindia/repositories)
  if [[ "$http_code" -ge 200 && "$http_code" -lt 400 ]]; then
    echo -e "[ ${BGREEN}OK${NC} ] ... Opscruise Docker repo \"https://hub.docker.com/orgs/opscruiseindia/repositories\" is reachable. HTTP Status Code:\"${http_code}\""
    doc_hub=$(( doc_hub + 1 ))
  else
    echo -e "[ ${BRED}FAILED${NC} ] ... Opscruise Docker repo \"https://hub.docker.com/orgs/opscruiseindia/repositories\" is NOT reachable. HTTP Status Code:\"${http_code}\""
    err_count=$(( err_count + 1 ))
  fi
  echo
  sanity_check_pod
  echo -e "\t--> Checking connectivity to Opscruise Helm repo"
  http_code=$(kubectl exec -it ${oc_pod_name} -n ${OC_NAMESPACE} -- curl -n -s -o /dev/null -w "%{http_code}" --max-time 15 https://opscruise-helm.bitbucket.io)
  if [[ "$http_code" -ge 200 && "$http_code" -lt 400 ]]; then
    echo -e "[ ${BGREEN}OK${NC} ] ... Opscruise Helm repo \"https://opscruise-helm.bitbucket.io\" is reachable. HTTP Status Code:\"${http_code}\""
  else
    echo -e "[ ${BRED}FAILED${NC} ] ... Opscruise Helm repo \"https://opscruise-helm.bitbucket.io\" is NOT reachable. HTTP Status Code:\"${http_code}\""
    err_count=$(( err_count + 1 ))
  fi
  echo
  echo -e "\t--> Checking connectivity to Open Source repositories"
  for repo in ${repos[@]}; do
    http_code=$(kubectl exec -it ${oc_pod_name} -n ${OC_NAMESPACE} -- curl -n -s -o /dev/null -w "%{http_code}" --max-time 10 ${repo})
    if [[ "$http_code" -ge 200 && "$http_code" -lt 400 ]]; then
      echo -e "[ ${BGREEN}OK${NC} ] ... Opensource repo \"${repo}\" is reachable. HTTP Status Code:\"${http_code}\""
    else
      echo -e "[ ${BRED}FAILED${NC} ] ... Opensource repo \"${repo}\" is NOT reachable. HTTP Status Code:\"${http_code}\""
      err_count=$(( err_count + 1 ))
    fi
  done
  echo
  nc_call() {
    if $(kubectl exec -it ${oc_pod_name} -n ${OC_NAMESPACE} -- which nc &> /dev/null); then
      if $(kubectl exec -it ${oc_pod_name} -n ${OC_NAMESPACE} -- nc -zw10 ${ep_name} ${ep_port}); then
        echo -e "[ ${BGREEN}OK${NC} ] ... Target \"${ep_name}\" is reachable on port \"${ep_port}\""
      else
        echo -e "[ ${BRED}FAILED${NC} ] ... Unable to connect \"${ep_name}\" on port \"${ep_port}\""
        err_count=$(( err_count + 1 ))
      fi
    else
      if $(kubectl exec -it ${oc_pod_name} -n ${OC_NAMESPACE} -- /bin/bash -c "echo >/dev/tcp/${ep_name}/${ep_port} &>/dev/null"); then
        echo -e "[ ${BGREEN}OK${NC} ] ... Target \"${ep_name}\" is reachable on port \"${ep_port}\""
      else
        echo -e "[ ${BRED}FAILED${NC} ] ... Unable to connect \"${ep_name}\" on port \"${ep_port}\""
        err_count=$(( err_count + 1 ))
      fi
    fi
  }
  echo -e "\t--> Checking connectivity to Opscruise North Endpoint and Keycloak Server"
  if [ -f "./opscruise-values.yaml" ]; then
    ep_name=$(cat opscruise-values.yaml | grep "OPSCRUISE_ENDPOINT" | awk -F': ' '{print $2}' | sed s/[\"]//g | awk -F':' '{print $1}')
    ep_port=$(cat opscruise-values.yaml | grep "OPSCRUISE_ENDPOINT" | awk -F': ' '{print $2}' | sed s/[\"]//g | awk -F':' '{print $2}')
    nc_call
    ep_name=$(cat opscruise-values.yaml | grep "KEYCLOAK_URL" | awk -F': ' '{print $2}' | sed s/[\"]//g | awk -F'//' '{print $2}' | awk -F':' '{print $1}')
    ep_port=$(cat opscruise-values.yaml | grep "KEYCLOAK_URL" | awk -F': ' '{print $2}' | sed s/[\"]//g | awk -F'//' '{print $2}' | awk -F':' '{print $2}')
    nc_call
  else
    echo "File \"opscruise-values.yaml\" does not exist under the path \"$(pwd)\""
    echo -n "Do you wish to provide values now? (y/n): "
    read response
    if [[ "$response" == "y" || "$response" == "yes" ]]; then
      echo -n "Enter North Endpoint Name: "
      read ep_name
      echo -n "Enter North Endpoint Port: "
      read ep_port
      nc_call
    elif [[ "$response" == "n" || "$response" == "no" ]]; then
      echo "Skipping check..."
    else
      echo "Invalid Response \"${response}\". Skipping check..."
    fi
  fi
  echo
  echo -e "\t--> Checking connectivity to Kernel Headers Location"
  for i in ${lnx_distro[@]}; do
    if [ "$i" == "ubuntu" ]; then
      for j in ${ubuntu_kernel_loc[@]}; do
        ep_name=$(echo $j | awk -F':' '{print $1}')
        ep_port=$(echo $j | awk -F':' '{print $2}')
        nc_call
      done
    elif [ "$i" == "amzn" ]; then
      for j in ${amzn_kernel_loc[@]}; do
        ep_name=$(echo $j | awk -F':' '{print $1}')
        ep_port=$(echo $j | awk -F':' '{print $2}')
        nc_call
      done
    elif [ "$i" == "centos" ]; then
      for j in ${centos_kernel_loc[@]}; do
        ep_name=$(echo $j | awk -F':' '{print $1}')
        ep_port=$(echo $j | awk -F':' '{print $2}')
        nc_call
      done
    fi
  done
  echo
  echo -e "\t--> Checking whether kernel headers are installed or not"
  if [ $REDHAT == "true" ]; then
    echo "OS is Red Hat. Hence, skipping this check..."
    echo
  else
    cat << EOF > ./kernel_check.sh
#!/bin/sh

OS_ID=\$(cat /etc/os-release  | grep 'ID=' | egrep -v 'VERSION_ID|VARIANT_ID|PLATFORM_ID' | awk -F '=' '{print \$2}' | sed 's/["]//g')
echo "Host Linux Distribution ID : \$OS_ID"
echo "Host Kernel Version        : \$(uname -r)"
echo
if [ -d /usr/src ]; then
  if [ -d /usr/src/kernels ]; then
    echo "Available kernel headers under /usr/src/kernels/:"
    ls /usr/src/kernels/ | grep  -o \$(uname -r) && \
    echo -e "[ ${BGREEN}OK${NC} ] ... Linux kernel headers already installed" || \
    echo -e "[ ${BRED}FAILED${NC} ] ... Linux kernel headers not installed"
  else
    echo "Available kernel headers /usr/src/:"
    ls /usr/src/ | grep 'linux.*headers\|kernel.*headers' && \
    echo -e "[ ${BGREEN}OK${NC} ] ... Linux kernel headers already installed" || \
    echo -e "[ ${BRED}FAILED${NC} ] ... Linux kernel headers not installed"
  fi
else
  echo -e "[ ${BRED}FAILED${NC} ] ... Unable to mount kernel header location \"/usr/src/\" from Host."
fi
EOF
    kubectl exec -it ${oc_pod_name} -n ${OC_NAMESPACE} -- /bin/sh -c "`cat ./kernel_check.sh`"
  fi
  echo
  if [ "$err_count" -gt 0 ]; then
    echo "Status: \"$err_count\" error(s) found in Pre-check."
    echo
    exit 1
  else
    echo -e "\t\t########## Pre-checks are completed successfully ##########"
    echo
  fi
}

post-check() {
  err_count=0
  echo "--------------------------------------------------------"
  echo "----------------- Running Post-checks ------------------"
  echo "--------------------------------------------------------"
  echo
  echo -e "\t--> Ensure Opscruise South Components are running fine"
  for ns in ${OC_SOUTH_NAMESPACES[@]}; do
    echo "--> Checking status of Pods in \"${ns}\" Namespace..."
    unset out
    unset pod_len
    unset not_running
    out=$(kubectl get pods -n ${ns} -o jsonpath='{.items[*].metadata.name}')
    for pod in ${out[@]}; do
      stat=$(kubectl get pod ${pod} -n ${ns} -o jsonpath='{.status.containerStatuses[*].started}')
      len=$(echo "$stat" | wc -w)
      if [[ "$stat" == *"false"* ]]; then
        for (( i=0; i<${len}; i++ ));
        do
          con_stat=$(kubectl get pod ${pod} -n ${ns} -o jsonpath="{.status.containerStatuses[$i].started}")
          if [ "$con_stat" == "false" ]; then
            con_name=$(kubectl get pod ${pod} -n ${ns} -o jsonpath="{.status.containerStatuses[$i].name}")
            con_rsn=$(kubectl get pod ${pod} -n ${ns} -o jsonpath="{.status.containerStatuses[$i].state.waiting.reason}")
            if [ ! $con_rsn ]; then
              con_rsn="Unknown"
            fi
            data="$pod,$con_name,$con_rsn"
            not_running+=($(echo -e "$data"))
          fi
        done
      fi
    done
    pod_len=$(echo "${not_running[@]}" | wc -w)
    if [ $pod_len -eq 0 ]; then
      kubectl get pods -n ${ns}
      echo -e "[ ${BGREEN}OK${NC} ] ... All pods are running"
      echo
    else
      echo "Following pod(s) are not running..."
      started=0
      printf "|%-45s|%-20s|%-20s|\n" "POD_NAME" "CONTAINER_NAME" "REASON"
      echo "|---------------------------------------------|--------------------|--------------------|"
      for (( i=0; i<${pod_len}; i++ ));
      do
        pod_name=$(echo ${not_running[$i]} | awk -F',' '{print $1}')
        con_name=$(echo ${not_running[$i]} | awk -F',' '{print $2}')
        con_rsn=$(echo ${not_running[$i]} | awk -F',' '{print $3}')
        printf "|%-45s|%-20s|%-20s|\n" $pod_name $con_name $con_rsn
      done
      echo
      for (( i=0; i<${pod_len}; i++ ));
      do
        wt=0
        ss=$sleep_sec
        pod_name=$(echo ${not_running[$i]} | awk -F',' '{print $1}')
        con_name=$(echo ${not_running[$i]} | awk -F',' '{print $2}')
        con_rsn=$(echo ${not_running[$i]} | awk -F',' '{print $3}')
        cons=$(kubectl get pod ${pod_name} -n ${ns} -o jsonpath='{.spec.containers[*].name}')
        clen=$(echo "$cons" | wc -w)
        echo -n "Wating for container \"${con_name}\" in pod \"${pod_name}\" to start ."
        for (( k=0; k<=${pod_retry_count}; k++ )); do
          if [ $k -lt ${pod_retry_count} ]; then
            for (( y=0; y<${clen}; y++ ));
            do
              ccon=$(kubectl get pod ${pod_name} -n ${ns} -o jsonpath="{.status.containerStatuses[$y].name}")
              if [ "$ccon" == "$con_name" ]; then
                cstat=$(kubectl get pod ${pod_name} -n ${ns} -o jsonpath="{.status.containerStatuses[$y].started}")
                if [ "$cstat" == "false" ]; then
                  echo -n '.'
                  sleep $ss
                  wt=$(( wt + ss ))
                  break
                elif [ "$cstat" == "true" ]; then
                  echo " Started"
                  started=$(( started + 1 ))
                  break 2
                else
                  echo " Unknown Status"
                  break 2
                fi
              fi
            done
          else
            echo " Waited for ${wt} seconds. Pod didn't start"
          fi
        done
      done
      kubectl get pods -n ${ns}
      if [ "$pod_len" -eq "$started" ]; then
        echo -e "[ ${BGREEN}OK${NC} ] ... All pods are running"
      else
        echo -e "[ ${BRED}FAILED${NC} ] ... Few pods are NOT running"
        err_count=$(( err_count + 1 ))
        echo
      fi
    fi
  done
  echo
  echo -e "\t--> Check Image version of the components"
  op=$(kubectl get deploy,ds,statefulset -n opscruise -o custom-columns=Name:.metadata.name,Image:.spec.template.spec.containers[0].image)
  if [ $? -eq 0 ]; then
    echo "$op"
  else
    echo -e "[ ${BRED}FAILED${NC} ] ... Unable to fetch image versions"
    err_count=$(( err_count + 1 ))
  fi
  echo
  echo -e "\t--> Ensure Kafka endpoint can be connected properly"
  gws=$(kubectl get pods -n opscruise | egrep 'k8sgw|promgw' | awk '{print $1}')
  if [ ! -z "$gws" ]; then
    orig_IFS=$IFS
    IFS=$'\n'
    for g in $gws; do
      echo "--> Checking whether \"$g\" is connected to Kafka or not"
      co=$(kubectl logs $g -n opscruise | grep -iw Connected)
      if [ $? -eq 0 ]; then
        echo "$co"
        echo -e "[ ${BGREEN}OK${NC} ] ... Connected successfully"
        echo
      else
        echo -e "[ ${BRED}FAILED${NC} ] ... Unable to connect to kafka endpoint"
        err_count=$(( err_count + 1 ))
        echo
      fi
    done
    IFS=$orig_IFS
  else
    echo -e "[ ${BRED}FAILED${NC} ] ... K8sGW and PromGW not present in \"Opscruise\" namespace"
    err_count=$(( err_count + 1 ))
    echo
  fi
  sanity_check_pod
  echo -e "\t--> Ensure Infra Gateways are able to connect to respective Cloud using provided credentials"
  ig=$(kubectl get pods -n opscruise | egrep "aws|azure|gcp" | awk '{print $1}')
  if [ ! -z "$ig" ]; then
    orig_IFS=$IFS
    IFS=$'\n'
    for i in $ig; do
      if [[ "$i" == *"azuregw"* ]]; then
        echo "--> Checking whether \"$i\" is able to connectt to \"Azure\" cloud"
        io=$(kubectl logs $i -n opscruise | grep -wi Connected | awk NR==1)
        if [ $? -eq 0 ]; then
          echo "$io"
          echo -e "[ ${BGREEN}OK${NC} ] ... Authentication successful"
        else
          echo -e "[ ${BRED}FAILED${NC} ] ... Unable to connect to the cloud. Please check the credentials provided."
          err_count=$(( err_count + 1 ))
        fi
      elif [[ "$i" == *"awsgw"* ]]; then
        echo "--> Checking whether \"$i\" is able to connectt to \"AWS\" cloud"
        if [ -f 'opscruise-values.yaml' ]; then
          export AWS_REGION=$(cat opscruise-values.yaml | grep region | head -1 | awk -F': ' '{print $2}' | sed s/[\"]//g)
          export AWS_ACCESS_KEY_ID=$(cat opscruise-values.yaml | grep aws_access_key_id | head -1 | awk -F': ' '{print $2}' | sed s/[\"]//g)
          export AWS_SECRET_ACCESS_KEY=$(cat opscruise-values.yaml | grep aws_secret_access_key | head -1 | awk -F': ' '{print $2}' | sed s/[\"]//g)
          iam=$(kubectl exec -it ${oc_pod_name} -n ${OC_NAMESPACE} -- /bin/sh -c "export AWS_REGION=${AWS_REGION};export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID};export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY};aws sts get-caller-identity")
          if [ $? -eq 0 ]; then
            echo -e "[ ${BGREEN}OK${NC} ] ... Authentication successful"
          else
            echo -e "[ ${BRED}FAILED${NC} ] ... Unable to connect to the cloud. Please check the credentials provided."
            err_count=$(( err_count + 1 ))
          fi
        else
          echo "File \"opscruise-values.yaml\" is not present in $(pwd). Skipping..."
        fi
      elif [[ "$i" == *"gcpgw"* ]]; then
        echo "--> Checking whether \"$i\" is able to connectt to \"GCP\" cloud"
      else
        echo -e "[ ${BRED}FAILED${NC} ] ... Invalid InfraGW \"$i\""
        err_count=$(( err_count + 1 ))
      fi
    done
    IFS=$orig_IFS
  else
    echo "No InfraGWs deployed in \"Opscruise\" namespace. Skipping..."
  fi
  echo
  echo -e "\t--> Checking whether kernel headers are installed or not"
  if [ $REDHAT == "true" ]; then
    echo "OS is Red Hat. Hence, skipping this check..."
    echo
  else
    cat << EOF > ./kernel_check.sh
#!/bin/sh

OS_ID=\$(cat /etc/os-release  | grep 'ID=' | egrep -v 'VERSION_ID|VARIANT_ID|PLATFORM_ID' | awk -F '=' '{print \$2}' | sed 's/["]//g')
echo "Host Linux Distribution ID : \$OS_ID"
echo "Host Kernel Version        : \$(uname -r)"
echo
if [ -d /usr/src ]; then
  if [ -d /usr/src/kernels ]; then
    echo "Available kernel headers under /usr/src/kernels/:"
    ls /usr/src/kernels/ | grep  -o \$(uname -r) && \
    echo -e "[ ${BGREEN}OK${NC} ] ... Linux kernel headers already installed" || \
    echo -e "[ ${BRED}FAILED${NC} ] ... Linux kernel headers not installed"
  else
    echo "Available kernel headers /usr/src/:"
    ls /usr/src/ | grep 'linux.*headers\|kernel.*headers' && \
    echo -e "[ ${BGREEN}OK${NC} ] ... Linux kernel headers already installed" || \
    echo -e "[ ${BRED}FAILED${NC} ] ... Linux kernel headers not installed"
  fi
else
  echo -e "[ ${BRED}FAILED${NC} ] ... Unable to mount kernel header location \"/usr/src/\" from Host."
fi
EOF
    ne=$(kubectl get pods -n opscruise | grep oc-node-exporter | awk 'NR==1 {print $1}')
    kubectl exec -it ${ne} -n opscruise -- /bin/sh -c "`cat ./kernel_check.sh`"
  fi
  echo
  echo -e "\t--> Check whether Prometheus is able to scrape exporters and other components"
  prom_ip=$(kubectl get pods -n collectors -o wide | grep prometheus | awk '{print $6}')
  prom_tgt=$(kubectl exec -it ${oc_pod_name} -n ${OC_NAMESPACE} -- /bin/sh -c "curl -s http://${prom_ip}:9090/api/v1/targets?state=active | jq --raw-output '.data.activeTargets[] | "Service: \(.discoveredLabels.__meta_kubernetes_service_name // .discoveredLabels.__meta_kubernetes_pod_label_opscruiseProduct), Instance: \(.labels.instance), Health: \(.health)"'")
  echo "$prom_tgt"
  echo
  if [ "$err_count" -gt 0 ]; then
    echo "Status: \"$err_count\" error(s) found in Post-check."
    echo
    exit 1
  else
    echo -e "\t\t########## Post-checks are completed successfully ##########"
    echo
  fi
}


if [ "$chk_cond" == "pre-check" ]; then
  pre-requisite
  pre-check
elif [ "$chk_cond" == "post-check" ]; then
  pre-requisite
  post-check
elif [ "$chk_cond" == "--help" ]; then
  usage
  exit 0
elif [ "$chk_cond" == "--cleanup" ]; then
  exit 0
else
  usage
  exit 1
fi
