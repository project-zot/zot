#!/bin/bash

input_file=""
source_tag=""
destination_tags=""
registry=""
debug=0

while (( "$#" )); do
    case $1 in
        -r|--registry)
            if [ -z "$2" ]; then
                echo "Option registry requires an argument"
                exit 1
            fi
            registry=${2};
            shift 2
            ;;
        --destination-tags)
            if [ -z "$2" ]; then
                echo "Option destination-tag requires an argument"
                exit 1
            fi
            destination_tags=${2}
            shift 2
            ;;
        --source-tag)
            if [ -z "$2" ]; then
                echo "Option source-tag requires an argument"
                exit 1
            fi
            source_tag=${2}
            shift 2
            ;;
        -f|--file)
            if [ -z "$2" ]; then
                echo "Option file requires an argument"
                exit 1
            fi
            input_file=${2}
            shift 2
            ;;
        -d|--debug)
            debug=1
            shift 1
            ;;
        --)
            shift 1
            break
            ;;
        *)
            break
            ;;
    esac
done

if [ -z "${registry}" ]; then
    echo "Parameter --registry is mandatory"
    exit 1
fi

if [ -z "${source_tag}" ]; then
    echo "Parameter --source-tag is mandatory"
    exit 1
fi

if [ -z "${destination_tags}" ]; then
    destination_tags=${source_tag}
    echo "Parameter --destination-tags is not provided, will use value of --source-tag: ${destination_tags}"
fi

if [ -z "${input_file}" ]; then
    echo "Parameter --file is mandatory"
    exit 1
fi

function verify_prerequisites {
    mkdir -p ${data_dir}

    command -v regctl
    if [ $? -ne 0 ]; then
        echo "you need to install regctl as a prerequisite"
        exit 1
    fi

    command -v jq
    if [ $? -ne 0 ]; then
        echo "you need to install jq as a prerequisite"
        return 1
    fi

    return 0
}

if [ ${debug} -eq 1 ]; then
    set -x
    regctl_cmd="${regctl_cmd} -v debug"
fi

target_repo=$(jq -r -c ".target_repo" ${input_file})
source_repos=$(jq -r -c '.source_repos[]' ${input_file})

regctl_cmd="regctl"

digest_params=""
for repo in ${source_repos[@]}; do
    echo "identifying digest for ${registry}/${repo}:${source_tag}"
    digest=$(${regctl_cmd} image digest ${registry}/${repo}:${source_tag})
    echo "identified digest ${digest} for ${registry}/${repo}:${source_tag}"

    ${regctl_cmd} image copy ${registry}/${repo}:${source_tag} ${registry}/${target_repo}@${digest}

    digest_params="--digest ${digest} ${digest_params}"
done

destination_tags_array=($destination_tags)

echo "creating index ${registry}/${target_repo}:${destination_tags_array[0]}"
${regctl_cmd} index create ${registry}/${target_repo}:${destination_tags_array[0]} ${digest_params}

for destination_tag in ${destination_tags_array[@]:1}; do
    echo "tagging ${registry}/${target_repo}:${destination_tags_array[0]} as ${registry}/${target_repo}:${destination_tag}"
    ${regctl_cmd} image copy ${registry}/${target_repo}:${destination_tags_array[0]} ${registry}/${target_repo}:${destination_tag}
done
