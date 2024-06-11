#!/bin/bash
IsSystemLabel() {
    # $label_info=$1
    if [[   $1 =~ '"k8s-app":"kube-proxy"' || 
            $1 =~ '"k8s-app":"calico-node"' || 
            $1 =~ '"k8s-app":"calico-typha"' || 
            $1 =~ '"k8s-app":"calico-kube-controllers"' || 
            $1 =~ '"k8s-app":"kube-dns"' || 
            $1 =~ '"k8s-app":"konnectivity-agent"' || 
            $1 =~ '"kamaji.clastix.io/component":"konnectivity-agent"' || 
            $1 =~ '"component":"etcd"' || 
            $1 =~ '"component":"kube-controller-manager"' || 
            $1 =~ '"component":"kube-scheduler"' || 
            $1 =~ '"component":"kube-apiserver"' || 
            $1 =~ '"tier":"control-plane"' ]]; then
        return 0 # true
    else
        return 1 # false
    fi
}

IsVContainerLabel() {
    # $label_info=$1
    if [[   $1 =~ '"app.kubernetes.io/instance":"vcontainer"' || 
            $1 =~ '"k8s-app":"magnum-auto-healer"' || 
            $1 =~ '"app":"csi-cinder-controllerplugin"' || 
            $1 =~ '"app":"csi-cinder-nodeplugin"' || 
            $1 =~ '"app":"cluster-autoscaler"' ]]; then

        if [[ $1 =~ '"app.kubernetes.io/name":"ingress-nginx"' ]]; then
            return 1 # false
        fi

        return 0 # true
    else
        return 1 # false
    fi
}

IsVKSMarkOriginLabel() {
    # $label_info=$1
    if [[   $1 =~ '"vngcloud.vn/origin-resource":"true"' ]]; then
        return 0 # true
    else
        return 1 # false
    fi
}

IsGKELabel() {
    # $label_info=$1
    if [[   $1 =~ '"k8s-app":"glbc"' || 
            $1 =~ '"k8s-app":"gcp-compute-persistent-disk-csi-driver"' || 
            $1 =~ '"k8s-app":"konnectivity-agent-autoscaler"' || 
            $1 =~ '"k8s-app":"konnectivity-agent"' || 
            $1 =~ '"k8s-app":"kube-dns-autoscaler"' || 
            $1 =~ '"k8s-app":"event-exporter"' || 
            $1 =~ '"k8s-app":"fluentbit-gke"' || 
            $1 =~ '"component":"fluentbit-gke"' || 
            $1 =~ '"component":"kube-proxy"' || 
            $1 =~ '"k8s-app":"kube-proxy"' || 
            $1 =~ '"k8s-app":"metadata-proxy"' || 
            $1 =~ '"k8s-app":"nccl-fastsocket-installer"' || 
            $1 =~ '"k8s-app":"runsc-metric-server"' || 
            $1 =~ '"k8s-app":"tpu-device-plugin"' || 
            $1 =~ '"k8s-app":"nvidia-gpu-device-plugin"' || 
            $1 =~ '"k8s-app":"gke-metrics-agent"' ]]; then
        return 0 # true
    else
        return 1 # false
    fi
}

IsEKSLabel() {
    # $label_info=$1
    if [[   $1 =~ '"k8s-app":"aws-node"' || 
            $1 =~ '"eks.amazonaws.com/component":"coredns"' || 
            $1 =~ '"app.kubernetes.io/instance":"eks-pod-identity-agent"' || 
            $1 =~ '"app.kubernetes.io/instance":"aws-vpc-cni"' ]]; then
        return 0 # true
    else
        return 1 # false
    fi
}

GetNamespaceResourceLabel () {
    # namespace=$1

    # Get all resources in the specified namespace and extract their labels
    resource_labels=$(kubectl api-resources --verbs=list --namespaced -o name | xargs -n 1 kubectl get --show-kind --ignore-not-found --namespace="$1" -o json | \
        jq -c '.items[] | {kind: .kind, name: .metadata.name, labels: .metadata.labels}')

    # Store the labels in an array
    readarray -t label_list <<< "$resource_labels"

    arr="${label_list[@]}"
    for a in $arr; do
        echo $a
    done
}

GetClusterResourceLabel () {
    # Get all resources in the specified namespace and extract their labels
    resource_labels=$(kubectl api-resources --namespaced=false --verbs=list -o name | xargs -n 1 kubectl get --show-kind --ignore-not-found -o json | \
        jq -c '.items[] | {kind: .kind, name: .metadata.name, labels: .metadata.labels}')

    # Store the labels in an array
    readarray -t label_list <<< "$resource_labels"

    arr="${label_list[@]}"
    for a in $arr; do
        echo $a
    done
}

GetNamespace () {
    # Get list of namespaces
    namespaces=$(kubectl get namespaces -o=jsonpath='{.items[*].metadata.name}')
    for ns in $namespaces; do
        echo $ns
    done
}

mark_volume () {
    # Get list of namespaces
    namespaces=$(GetNamespace)

    # Loop over each namespace
    for namespace in $namespaces; do
        if [[ "$namespace" == "velero" ]]; then
            continue
        fi
        # echo "Namespace: $namespace"
        # Get list of Pods in the namespace
        pods=$(kubectl get pods -n "$namespace" -o=jsonpath='{.items[*].metadata.name}')
        # Loop over each Pod
        for pod in $pods; do
            volumes=$(kubectl get pod "$pod" -n "$namespace" -o=jsonpath='{.spec.volumes[*]}')
            pvc_names=""
            for volume in $volumes; do
                # echo $volume
                if [[ $volume =~ persistentVolumeClaim ]]; then
                    pvc_name=$(echo "$volume" | jq -r '.name')  # Uses jq to parse JSON and extract 'name'
                    pvc_names="${pvc_names},${pvc_name}"  # Add PVC name with comma separator
                fi
            done

            if [[ ! -z "$pvc_names" ]]; then
                echo "kubectl -n $namespace annotate pod/$pod backup.velero.io/backup-volumes=${pvc_names:1}"
                if [[ $isConfirmed == true ]]; then
                    kubectl -n $namespace annotate pod/$pod backup.velero.io/backup-volumes=${pvc_names:1}
                fi
            fi
        done
    done
}

unmark () {
    # Get list of namespaces
    namespaces=$(GetNamespace)

    # Loop over each namespace
    for namespace in $namespaces; do
        if [[ "$namespace" == "velero" ]]; then
            continue
        fi
        # echo "Namespace: $namespace"
        # Get list of Pods in the namespace
        pods=$(kubectl get pods -n "$namespace" -o=jsonpath='{.items[*].metadata.name}')
        # Loop over each Pod
        for pod in $pods; do
            annotations=$(kubectl get pod "$pod" -n "$namespace" -o=jsonpath='{.metadata.annotations}')
            if [[ $annotations =~ "backup.velero.io/backup-volumes" ]]; then
                echo "kubectl -n $namespace annotate pod/$pod backup.velero.io/backup-volumes-"
                if [[ $isConfirmed == true ]]; then
                    kubectl -n $namespace annotate pod/$pod backup.velero.io/backup-volumes-
                fi
            fi
        done
    done


    namespace="kube-system"
    resource_labels=$(GetNamespaceResourceLabel $namespace)
    for label_info in $resource_labels; do
        if [[   $label_info =~ '"velero.io/exclude-from-backup":"true"' ]]; then
            echo "kubectl -n $namespace label $(echo $label_info | jq -r '.kind')/$(echo $label_info | jq -r '.name') velero.io/exclude-from-backup-"
            if [[ $isConfirmed == true ]]; then
                kubectl -n $namespace label $(echo $label_info | jq -r '.kind')/$(echo $label_info | jq -r '.name') velero.io/exclude-from-backup-
            fi
        else
            : # do nothing
            # echo "Get this resource: $label_info"
        fi
    done

    resource_labels=$(GetClusterResourceLabel)
    for label_info in $resource_labels; do
        if [[   $label_info =~ '"velero.io/exclude-from-backup":"true"' ]]; then
            echo "kubectl label $(echo $label_info | jq -r '.kind')/$(echo $label_info | jq -r '.name') velero.io/exclude-from-backup-"
            if [[ $isConfirmed == true ]]; then
                kubectl label $(echo $label_info | jq -r '.kind')/$(echo $label_info | jq -r '.name') velero.io/exclude-from-backup-
            fi
        else
            : # do nothing
            # echo "Get this resource: $label_info"
        fi
    done
}

mark_exclude () {
    # Namespace to query
    namespace="kube-system"
    resource_labels=$(GetNamespaceResourceLabel $namespace)

    # Loop over each label and print it
    for label_info in $resource_labels; do
        # echo "Resource Label: $label_info"

        if  IsSystemLabel $label_info || IsVContainerLabel $label_info || IsGKELabel $label_info || IsEKSLabel $label_info ; then
            if [[ $label_info =~ 'ingress' ]]; then
                continue
            fi
            echo "kubectl -n $namespace label $(echo $label_info | jq -r '.kind')/$(echo $label_info | jq -r '.name') velero.io/exclude-from-backup=true"
            if [[ $isConfirmed == true ]]; then
                kubectl -n $namespace label $(echo $label_info | jq -r '.kind')/$(echo $label_info | jq -r '.name') velero.io/exclude-from-backup=true
            fi
        else
            : # do nothing
            # echo "Get this resource: $label_info"
        fi
    done

    resource_labels=$(GetClusterResourceLabel)
    for label_info in $resource_labels; do

        if  IsSystemLabel $label_info || IsVContainerLabel $label_info || IsGKELabel $label_info || IsEKSLabel $label_info ; then
            if [[ $label_info =~ 'ingress' ]]; then
                continue
            fi
            echo "kubectl label $(echo $label_info | jq -r '.kind')/$(echo $label_info | jq -r '.name') velero.io/exclude-from-backup=true"
            if [[ $isConfirmed == true ]]; then
                kubectl label $(echo $label_info | jq -r '.kind')/$(echo $label_info | jq -r '.name') velero.io/exclude-from-backup=true
            fi
        else
            : # do nothing
            # echo "Get this resource: $label_info"
        fi
    done
}

mark_origin () {
    namespaces=$(GetNamespace)
    for namespace in $namespaces; do
        if [[ "$namespace" == "velero" ]]; then
            continue
        fi
        
        resource_labels=$(GetNamespaceResourceLabel $namespace)
        for label_info in $resource_labels; do
            kind=$(echo $label_info | jq -r '.kind')
            if [[ $kind == "" ]]; then
                continue
            fi
            echo "kubectl -n $namespace label $kind/$(echo $label_info | jq -r '.name') vngcloud.vn/origin-resource=true"
            if [[ $isConfirmed == true ]]; then
                kubectl -n $namespace label $kind/$(echo $label_info | jq -r '.name') vngcloud.vn/origin-resource=true
            fi
        done
    done

    resource_labels=$(GetClusterResourceLabel)
    for label_info in $resource_labels; do
        kind=$(echo $label_info | jq -r '.kind')
        if [[ $kind == "" ]]; then
            continue
        fi
        echo "kubectl label $kind/$(echo $label_info | jq -r '.name') vngcloud.vn/origin-resource=true"
        if [[ $isConfirmed == true ]]; then
            kubectl label $kind/$(echo $label_info | jq -r '.name') vngcloud.vn/origin-resource=true
        fi
    done
}

reset () {
    namespaces=$(GetNamespace)
    for namespace in $namespaces; do
        if [[ "$namespace" == "velero" ]]; then
            continue
        fi
        
        resource_labels=$(GetNamespaceResourceLabel $namespace)

        for label_info in $resource_labels; do
            if  IsSystemLabel $label_info || IsVKSMarkOriginLabel $label_info ; then
                : # do nothing
            else
                kind=$(echo $label_info | jq -r '.kind')
                if [[ $kind == "" ]]; then
                    continue
                fi
                echo "kubectl -n $namespace delete $kind $(echo $label_info | jq -r '.name')"
                if [[ $isConfirmed == true ]]; then
                    kubectl -n $namespace delete $(echo $label_info | jq -r '.kind') $(echo $label_info | jq -r '.name')
                fi
            fi
        done
    done

    resource_labels=$(GetClusterResourceLabel)
    for label_info in $resource_labels; do
        if  IsSystemLabel $label_info || IsVKSMarkOriginLabel $label_info ; then
            : # do nothing
        else
            kind=$(echo $label_info | jq -r '.kind')
            if [[ $kind == "" ]]; then
                continue
            fi
            echo "kubectl delete $kind $(echo $label_info | jq -r '.name')"
            if [[ $isConfirmed == true ]]; then
                kubectl delete $(echo $label_info | jq -r '.kind') $(echo $label_info | jq -r '.name')
            fi
        fi
    done
}

check_hostPath () {
    namespaces=$(kubectl get namespaces -o=jsonpath='{.items[*].metadata.name}')
    for namespace in $namespaces; do
        if [[ "$namespace" == "velero" ]]; then
            continue
        fi
        echo "    ns: $namespace"
        pods=$(kubectl get pods -n "$namespace" -o=jsonpath='{.items[*].metadata.name}')
        # Loop over each Pod
        for pod in $pods; do
            volumes=$(kubectl get pod "$pod" -n "$namespace" -o=jsonpath='{.spec.volumes[*]}')
            if [[ $volumes =~ hostPath ]]; then
                echo "      - pod: $pod"
                for volume in $volumes; do
                    if [[ $volume =~ hostPath ]]; then
                        path=$(echo "$volume" | jq -r '.hostPath' | jq -r '.path')  # Uses jq to parse JSON and extract 'name'
                        echo "          $path"
                    fi
                done
            fi
        done
    done
}

check_node_label () {
    
    declare -a ignored_labels=(
        "beta.kubernetes.io/arch" 
        "beta.kubernetes.io/os"
        "kubernetes.io/arch"
        "kubernetes.io/hostname"
        "kubernetes.io/os"
    )
    
    
    # Get node information in JSON format
    node_info=$(kubectl get nodes -o json)

    # Extract node names
    node_names=$(echo "$node_info" | jq -r '.items[].metadata.name')

    # Loop over each node
    while IFS= read -r node; do
        # Extract labels for the current node
        labels=$(echo "$node_info" | jq -r --arg node "$node" '.items[] | select(.metadata.name == $node) | .metadata.labels | to_entries[] | "\(.key): \(.value)"')
        # labels=$(echo "$node_info" | jq -r --arg node "$node" '.items[] | select(.metadata.name == $node) | .metadata.labels | to_entries[] | "\(.key)"')

        # Loop over each label of the current node and print it
        while IFS= read -r label; do
            # Check if the label is in the list of ignored labels
            is_ignored=false
            for ignored_label in "${ignored_labels[@]}"; do
                if [[ "$label" =~ "$ignored_label" ]]; then
                    is_ignored=true
                    break
                fi
            done
            if [[ $is_ignored == true ]]; then
                continue
            fi
            echo "      - $label"
        done <<< "$labels"
    done <<< "$node_names"
}

check_node_taint () {
    # Get node information in JSON format
    node_info=$(kubectl get nodes -o json)

    # Extract node names
    node_names=$(echo "$node_info" | jq -r '.items[].metadata.name')

    # Loop over each node
    while IFS= read -r node; do
        # Extract taints for the current node
        taints=$(echo "$node_info" | jq -r --arg node "$node" '.items[] | select(.metadata.name == $node) | .spec.taints | if . == null then [] else . end | .[] | "\(.key): \(.value) (\(.effect))"')

        # Loop over each taint of the current node and print it
        while IFS= read -r taint; do
            echo "      - $taint"
        done <<< "$taints"
    done <<< "$node_names"
}

check () {
    ################# hostPath volumes
    echo "*** Check these hostPath volumes, they are be ignored in backup. Please convert to persistent volume to backup."
    echo ""
    check_hostPath

    ############################## label for node
    echo ""
    echo "*** Ensure these labels not in use or exist in target cluster's nodes"
    echo ""
    check_node_label
    
    ############################## taint for node
    echo ""
    echo "*** Ensure these taints exist in target cluster's nodes"
    echo ""
    check_node_taint

    ############################## mark volume
    echo ""
    echo "*** These PersistentVolumes are not marked for backup"
    echo ""
    mark_volume
    ############################## mark exclude
    echo ""
    echo "*** These resources are not marked to exclude from backup"
    echo ""
    mark_exclude
}

opt=$1
confirm=$2
isConfirmed=false
if [[ "$confirm" == "--confirm" || "$confirm" == "-c" ]]; then
    isConfirmed=true
fi

case $opt in
mark_volume)
    mark_volume
    ;;
unmark)
    unmark
    ;;
mark_exclude)
    mark_exclude
    ;;
reset)
    reset
    ;;
mark_origin)
    mark_origin
    ;;
check_hostPath)
    check_hostPath
    ;;
check_node_label)
    check_node_label
    ;;
check_node_taint)
    check_node_taint
    ;;
check)
    check
    ;;
*)
    echo "Usage: $0 "
    echo ""
    echo "          mark_volume         Mark all PVC volumes in pods for backup"
    echo "          mark_exclude        Mark system resource to exclude from backup"
    echo "          unmark              Unmark above"
    echo ""
    echo "          check               check total"
    echo "          check_hostPath      list all hostPath volumes in pods"
    echo "          check_node_label    list all labels uncommon in nodes"
    echo "          check_node_taint    list all taints in nodes"
    echo ""
    echo "          [--confirm|-c]      Run command automatically"
    exit 1
    ;;
esac

