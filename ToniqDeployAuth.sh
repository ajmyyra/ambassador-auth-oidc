#!/usr/bin/env bash
# set expandtab tabstop=2 shiftwidth=2 softtabstop=2 */

##############################################################
#
# DevOps agent post-Bamboo script for toniq-ambassador-auth-oidc
#   (only root user can run docker)
#
#  Builds Notebook and Hive  docker images and publishes to ECRs
#
#  Input environment values expected
#   - ECR_REGISTRY # ECR URL ie. 481935479534.dkr.ecr.us-east-1.amazonaws.com
#   - BUILD_AWS_ENV # ie. sit [dev, sit, prod]
#
##############################################################

set -o errexit

##############################################################
# Utils
##############################################################
trim() {
    local var="$*"
    # remove leading whitespace characters
    var="${var#"${var%%[![:space:]]*}"}"
    # remove trailing whitespace characters
    var="${var%"${var##*[![:space:]]}"}"   
    printf '%s' "$var"
}

##############################################################
# ENV check
##############################################################

echo "Checking to ensure required ENV exists..."

requiredEnvs=(ECR_REGISTRY BUILD_AWS_ENV)
for env in ${requiredEnvs[@]}; do
  if [[ -z "${!env}" ]]; then
    echo "$env value required"
    exit 1
  fi
done

# trim spaces
ECR_REGISTRY="$(trim "${ECR_REGISTRY}")"
BUILD_AWS_ENV="$(trim "${BUILD_AWS_ENV}")"

echo "ECR_REGISTRY: ${ECR_REGISTRY}"
echo "BUILD_AWS_ENV: ${BUILD_AWS_ENV}"

echo "Get the latest docker cred via aws..."
aws ecr get-login-password --region us-east-1 | sudo docker login --username AWS --password-stdin ${ECR_REGISTRY}

echo "Get dockerhub.com credentials from secret"
aws secretsmanager get-secret-value --secret-id /${BUILD_AWS_ENV}/toniq-apiv1/dockercred/docai --region us-east-1 | grep SecretString | cut -f 4 -d '"' | sudo docker login --username anthembuildacct --password-stdin

##############################################################
# HUB
##############################################################
echo "Build and publish to ECR process for HUB..."

# Prefix must be the partial prefix for all 
ECR_PREFIX=${ECR_REGISTRY}/antm-docai-${BUILD_AWS_ENV}-ecr-

echo "ECR_PREFIX: ${ECR_PREFIX}"
sudo ./build.sh ${ECR_PREFIX}
