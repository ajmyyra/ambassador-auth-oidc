#!/bin/bash

# this script will default to the Toniq GCR url but can be called and passed any registry/repo url like so:
# ./build.sh 12345.dkr.ecr.us-east-1.amazonaws.com/toniq

BASE_REPOSITORY_URL=${1:-us.gcr.io/terraform-254700/toniq/}
VERSION_TAG=`cat VERSION | tr -d '\n'`
ECR_REPOSITORY_URL=484285707936.dkr.ecr.us-west-2.amazonaws.com/antm-docai-dev-ecr-toniq-ambassador-auth-oidc:$VERSION_TAG

docker build -t ${BASE_REPOSITORY_URL}toniq-ambassador-auth-oidc:$VERSION_TAG -t ${BASE_REPOSITORY_URL}toniq-ambassador-auth-oidc:latest -t $ECR_REPOSITORY_URL .

docker push ${BASE_REPOSITORY_URL}toniq-ambassador-auth-oidc:$VERSION_TAG
docker push ${BASE_REPOSITORY_URL}toniq-ambassador-auth-oidc:latest

if [ -d .git ]
   then
       echo "Getting ECR credentials"
       mkdir -p ~/.aws
       gcloud secrets versions access --project terraform-254700 2 --secret aws-ecr-user > ~/.aws/credentials || echo "failed"

       echo "Getting docker credentials"
       aws ecr get-login-password --profile default  --region us-west-2 | docker login --username AWS --password-stdin 484285707936.dkr.ecr.us-west-2.amazonaws.com/antm-docai-dev-ecr-toniq-mlflow || echo "failed"
       echo "Pushing image to ECR"
       docker push ${ECR_REPOSITORY_URL}
fi
