import boto3

session = boto3.Session(profile_name='my-role')
print(session.client("sts").get_caller_identity())
iam = session.client("iam")

# user_id = self.get_user_id(domino_api_key)
managed_user_policies = iam.list_attached_user_policies(UserName='integration-test')
for up in managed_user_policies:
    print(up)
    # self._iam.self._iam.l

