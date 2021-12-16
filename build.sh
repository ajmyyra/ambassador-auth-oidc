#!/bin/bash

# this script will default to the Toniq GCR url but can be called and passed any registry/repo url like so:
# ./build.sh 12345.dkr.ecr.us-east-1.amazonaws.com/toniq

BASE_REPOSITORY_URL=${1:-us.gcr.io/terraform-254700/toniq}
VERSION_TAG=`cat VERSION | tr -d '\n'`

docker build -t $BASE_REPOSITORY_URL/ambassador-auth-oidc:$VERSION_TAG -t $BASE_REPOSITORY_URL/ambassador-auth-oidc:latest .

docker push $BASE_REPOSITORY_URL/ambassador-auth-oidc:$VERSION_TAG
docker push $BASE_REPOSITORY_URL/ambassador-auth-oidc:latest
