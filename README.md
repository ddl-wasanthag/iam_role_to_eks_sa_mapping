# User Documentation for IAM to K8s Service Account Mapping for Domino

This is a user document to allow Domino Administrators to map user workspaces to IAM roles. When the user starts a workspace,
the workspace will be configured to with a *aws config* file with a profile for each aws role the user is allowed to assume. the
name of the profile will the `aws role name` (not ARN).

The user should be able to use the boto3 api simply by selecting a profile-

```python
import boto3
role_arn_profile_name = 'asset-update-bucket-role'
bucket_name = 'my_bucket'
session = boto3.session.Session(profile_name=role_arn_profile_name)
s3_client = session.client('s3')
for key in s3_client.list_objects(Bucket=bucket_name)['Contents']:
    print(key)
```

If the EKS cluster is in the same AWS account as the aws role being assumed the user can simply configure an environment 
variable `AWS_ROLE_ARN` (represented by one of the profiles) and start using the boto3 api-


```python
import os

eks_account_id = '11111111' #Provide your aws account id where the eks cluster is hosted
bucket_name = 'my_bucket'
os.environ['AWS_ROLE_ARN'] = f"arn:aws:iam::{eks_account_id}:role/valo-read-bucket-role"
import boto3.session
my_session = boto3.session.Session()
s3_client = my_session.client('s3')
for key in s3_client.list_objects(Bucket=bucket_name)['Contents']:
    print(key)
```

This approach cannot be used when the EKS Account Id and the account id where the AWS Roles are hosted are different. In 
that case the `AWS_CONFIG` file approach shown earlier is the only usable approach.

## User Runbook

For the selected list of  projects (by default all Domino Projects), when a user starts a workspaces, they will be able to execute an endpoint
using the code snippet below-
```python
import requests

import os

url = 'http://iam-sa-mapping-svc.domino-platform/map_iam_role_to_pod_sa'
headers = {"Content-Type" : "application/json",
           "X-Domino-Api-Key": os.environ['DOMINO_USER_API_KEY'] 
          }
data = {    
    "run_id" : os.environ['DOMINO_RUN_ID']
}

resp = requests.post(url,headers=headers,json=data)
# Writing to file
with open(os.environ['AWS_CONFIG_FILE'], "w") as f:
    # Writing data to a file
    f.write(resp.content.decode())
    
```

**This step can be automated which will allow the user to start using the profiles when the workspace starts up
without performing the additional step above**. This will be done using a side-car injected via a mutation inside the 
workspace pod.

The above code-snipped will populate the file referenced by the environment variable `AWS_CONFIG_FILE` (injected into the qualifying pods 
via a mutation). An example of such as file is-

```shell
[profile customer-list-bucket-role]
source_profile = src_valo-list-bucket-role
role_arn=arn:aws:iam::<ASSETS_AWS_ACCOUNT>:role/customer-list-bucket-role

[profile src_customer-list-bucket-role]
web_identity_token_file = /var/run/secrets/eks.amazonaws.com/serviceaccount/token
role_arn=arn:aws:iam::<EKS_AWS_ACCOUNT>:role/customer-list-bucket-role

[profile customer-read-bucket-role]
source_profile = src_valo-read-bucket-role
role_arn=arn:aws:iam::<ASSETS_AWS_ACCOUNT>:role/customer-read-bucket-role

[profile src_customer-read-bucket-role]
web_identity_token_file = /var/run/secrets/eks.amazonaws.com/serviceaccount/token
role_arn=arn:aws:iam::<EKS_AWS_ACCOUNT>:role/valo-read-bucket-role

[profile customer-update-bucket-role]
source_profile = src_valo-update-bucket-role
role_arn=arn:aws:iam::<ASSETS_AWS_ACCOUNT>:role/customer-update-bucket-role

[profile src_customer-update-bucket-role]
web_identity_token_file = /var/run/secrets/eks.amazonaws.com/serviceaccount/token
role_arn=arn:aws:iam::<EKS_AWS_ACCOUNT>:role/customer-update-bucket-role
```

Notice, in the above example, for every `customer*` profile, there is a source profile `src_customer*` profile. The
reason for this is, the EKS account is hosted in a separate AWS Account from the AWS Assets Account. For each role, the
user can assume in the `ASSET_AWS_ACCOUNT`, there is a corresponding role in the `EKS_AWS_ACCOUNT` which has a
cross account assume role permission for the corresponding `ASSET_AWS_ACCOUNT`. This constraint is imposed by AWS mechanism 
for IAM Role to EKS Service Account Mapping.

## Installation Steps

1. Configure your EKS cluster to support IAM Roles to EKS Service Account by following the [instructions](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)
   from the AWS documentation. At a high level this includes the following steps:

    - Creating an IAM OIDC provider for your cluster – You only complete this procedure once for each cluster. 
    - Configuring a Kubernetes service account to assume an IAM role – Complete this procedure for each unique set of permissions that you want an application to have. 
    - Configuring pods to use a Kubernetes service account – Domino Workspace/Job pods have a unique service account. The `domsed`
      mutation enables this step dynamically. AWS documentation assumes that service accounts are known in advance. However,
      this assumption does not hold true in case of Domino user pods. Hence we need the mutation to perform this step for us.
    - There a minor refinement needed for supporting cross account role permissions which is documented [here] (https://docs.aws.amazon.com/eks/latest/userguide/cross-account-access.html)
    
2. First the Domino Domsed framework needs to be installed.  `domsed` is an application for applying minor patches to 
the Kubernetes resources deployed by Domino. It is deployed as mutating admissions controller. In the event that 
`domsed` encounters an error, Kubernetes is configured to fall back to the original resource spec defined by Domino. 
This prevents a bug from breaking Domino. `domsed` is Domino-aware, meaning that it can apply patches selectively based on Hardware Tier, Project, User Id, 
or Organization. It is configured by managing Mutation custom resources which means that a single `domsed` deployment 
can apply many different patch configurations and this can be configured on the fly.

3. Next apply the following mutation - 
```yaml
apiVersion: apps.dominodatalab.com/v1alpha1
kind: Mutation
metadata:
  name: aws-iam-to-sa-mapping
  namespace: domino-platform
rules:
- labelSelectors: #Delete fsGroup key from context
  - "dominodatalab.com/workload-type in (Workspace,Job)"
  modifySecurityContext:
    context:
      fsGroup: 12574
- labelSelectors:
  - "dominodatalab.com/workload-type in (Workspace,Job)"
  insertContainer:
    containerType: app
    spec:
      command: [ "/bin/sh", "-c", "--" ]  
      args: [ "while true; do sleep 30; done;" ]
      image: busybox
      name: aws-config-file-generator
- labelSelectors:
  - "dominodatalab.com/workload-type in (Workspace,Job)"
  insertVolumeMounts:
    containerSelector:
    - aws-config-file-generator
    volumeMounts:
    - name: aws-config-file
      mountPath: /var/run/.aws
    - name: jwt-secret-vol 
      mountPath: /var/lib/domino/home/.api
      readOnly: true
- labelSelectors:
  - "dominodatalab.com/workload-type in (Workspace,Job)"
  insertVolumes:
  - name: aws-config-file
    emptyDir:
      sizeLimit: 500Mi
  - name: aws-user-token
    projected:
      defaultMode: 422
      sources:
      - serviceAccountToken:
          path: token
          expirationSeconds: 86400
          audience: sts.amazonaws.com
- labelSelectors:
  - "dominodatalab.com/workload-type in (Workspace,Job)"
  insertVolumeMounts:
    containerSelector:
    - run
    volumeMounts:
    - name: aws-config-file
      mountPath: /var/run/.aws
      readOnly: true
    - name: aws-user-token
      mountPath: /var/run/secrets/eks.amazonaws.com/serviceaccount/
      
- labelSelectors:
  - "dominodatalab.com/workload-type in (Workspace,Job)"
  modifyEnv:
    containerSelector:
    - run
    env:
    - name: AWS_WEB_IDENTITY_TOKEN_FILE
      value: /var/run/secrets/eks.amazonaws.com/serviceaccount/token
    - name: AWS_CONFIG_FILE
      value: /var/run/.aws/config
```
The key feature of K8s which enables this capability is the concept of [service account token volume projection](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#serviceaccount-token-volume-projection)
The Service Account Token Volume Projection feature of Kubernetes allows projection of time and audience-bound 
service account tokens into Pods. This feature is used by some applications to enhance security when using service accounts. 
*These tokens are separate from the default K8s service account tokens used to connect to the K8s API Server and 
disabled for user pods in Domino*. These tokens are issued by the IAM OIDC Provider configured in the AWS cluster and
are trusted by the AWS IAM which is how these tokens can be used to assume the appropriate IAM roles for the Pod.

The following two blogs explain the process well -

1. https://mjarosie.github.io/dev/2021/09/15/iam-roles-for-kubernetes-service-accounts-deep-dive.html
2. https://blog.mikesir87.io/2020/09/eks-pod-identity-webhook-deep-dive/

The documentation assumes that a pod can only assume one IAM role at a time. This is true if you use the EKS provided
mutation which requires the service account to be annotated with the appropriate AWS ROLE ARN. 

**However because Domino pods recieve a dynamically defined service account, we have refined this process to support all
the roles the user can assume by dynamically generated a *aws config* file with a K8s service defined for this purpose**

4. Which brings us to installing the Domino Service which makes this all come together. Install this service by 
   having the K8s Admin run the following command from the root folder of this git project-
   `./scripts/deploy.sh <SERVICE_DOCKER_IMAGE_TAG> <AWS_EKS_ACCOUNT_ID> <OIDC_PROVIDER> <OIDC_PROVIDER_AUDIENCE>`
   The parameters are as follows:
   - You can create the docker image by running the command `./scripts/create_and_push_docker_image.sh` . This script
     builds the docker image and publishes it. Note the tag you defined for this image. We assume `latest` for the purpose 
     of this document. `SERVICE_DOCKER_IMAGE_TAG==latest` 
   - `AWS_EKS_ACCOUNT_ID` is the AWS Account Id where your EKS cluster is installed 
   - `OIDC_PROVIDER` - ARN of the OIDC Provider. This can be obtained from you EKS cluster definition
   - `OIDC_PROVIDER_AUDIENCE` - We are using STS to generate tokens to allow role access into the asset aws account. We will
     assume this to be `sts.amazonaws.com`
     
5. Next open the script `deploy-add.sh`. This script updates config map which maps the roles in the `asset_aws_account` to the roles
   in the `eks_customer_account`
   

There is one additional wrinkle to solve. We do not know the mappings between the user and the roles. In this default implementation
we do this mapping using Domino Org membership. An example mapping defined in the `deploy-add.sh` is

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: domino-org-iamrole-mapping
data: {
    "iamrole-list-bucket":"arn:aws:iam::${asset_aws_account}:role/customer-list-bucket-role",
    "iamrole-read-bucket":"arn:aws:iam::${asset_aws_account}:role/customer-read-bucket-role",
    "iamrole-update-bucket":"arn:aws:iam::${asset_aws_account}:role/customer-update-bucket-role"
  }
EOF
```

This is usable but if there is a way to determine this information from AWS, it would be ideal. For example, a user in
`Identity Center` may be attached to a well known set of policies which allow the domino service to determine
which roles they can [assume](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_permissions-to-switch.html)

```json
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Action": "sts:AssumeRole",
    "Resource": "arn:aws:iam::account-id:role/Test*"
  }
}
```

The Domino Service which performs the mapping also runs as a IAM Role which can have permissions to read these policies
and dynamically determine the user to role mappings. A sample role this Domino Service assumes is 
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor1",
            "Effect": "Allow",
            "Action": "iam:*",
            "Resource": "arn:aws:iam::<EKS_ROLE>:role/customer*"
        }
    ]
}
```
This is essential to map the Pod SA to the appropriate role in the EKS Account, which in turn has the permissions to 
assume the corresponding role in the AWS Assets Account. An additional policy which can be attached to this role is
the ability to fetch the details of User/Policy mappings from the "Asset Account" which given the "AWS Identity Center"
user mapping will enable this service to fetch the role mappings for Domin user.


