function setup_cloud_services() {
    setup_s3 "us-east-2" "zot-storage-test"
    setup_dynamodb "us-east-2"
}

function teardown_cloud_services() {
    delete_s3_bucket "zot-storage-test"
    teardown_dynamodb "us-east-2"
}

function setup_s3() {
    local region=${1}
    local bucket=${2}
    awslocal s3 --region ${region} mb s3://${bucket}
}

function delete_s3_bucket() {
    local bucket=${1}
    awslocal s3 rb s3://${bucket} --force
}

function setup_dynamodb() {
    local region=${1}
    awslocal dynamodb --region ${region} \
        create-table \
        --table-name "BlobTable" \
        --attribute-definitions AttributeName=Digest,AttributeType=S \
        --key-schema AttributeName=Digest,KeyType=HASH \
        --provisioned-throughput ReadCapacityUnits=10,WriteCapacityUnits=5
}

function teardown_dynamodb() {
    local region=${1}
    awslocal dynamodb --region ${region} delete-table --table-name "BlobTable"
}
