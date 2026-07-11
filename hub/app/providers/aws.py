"""AWS EC2 provider.

Auth: standard boto3 credential chain (env vars, ~/.aws/credentials, IAM role).

MachineSpec mapping: machine_type = EC2 instance type ("t3.micro"),
region = AWS region ("us-east-1"). AMI is the latest Amazon Linux 2023,
resolved via the public SSM parameter so it never goes stale.
"""

import time

from .base import CloudProvider, ProviderError, ProvisionRequest, ProvisionResult
from .bootstrap import (
    SERVER_PORT,
    TURN_PORT,
    TURN_RELAY_PORTS,
    build_startup_script,
)

SECURITY_GROUP = "zeon-server"
AL2023_SSM_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


class AWSProvider(CloudProvider):
    name = "aws"

    def __init__(self):
        try:
            import boto3  # noqa: F401
        except ImportError as e:
            raise ProviderError("boto3 is not installed; pip install boto3") from e

    def provision(self, req: ProvisionRequest) -> ProvisionResult:
        import boto3

        region = req.spec.region
        ec2 = boto3.client("ec2", region_name=region)
        ssm = boto3.client("ssm", region_name=region)

        ami = ssm.get_parameter(Name=AL2023_SSM_PARAM)["Parameter"]["Value"]
        sg_id = self._ensure_security_group(ec2)

        response = ec2.run_instances(
            ImageId=ami,
            InstanceType=req.spec.machine_type,
            MinCount=1,
            MaxCount=1,
            SecurityGroupIds=[sg_id],
            UserData=build_startup_script(req.owner_id, req.owner_token),
            BlockDeviceMappings=[
                {
                    "DeviceName": "/dev/xvda",
                    "Ebs": {"VolumeSize": req.spec.disk_gb, "VolumeType": "gp3"},
                }
            ],
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": [
                        {"Key": "Name", "Value": f"zeon-{req.owner_id[3:11].lower()}"},
                        {"Key": "zeon", "Value": "routing-server"},
                    ],
                }
            ],
        )
        instance_id = response["Instances"][0]["InstanceId"]

        ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id])
        ip = self._wait_public_ip(ec2, instance_id)

        return ProvisionResult(
            resource_id=instance_id,
            address=f"https://{ip}:{SERVER_PORT}",
            meta={"region": region},
        )

    def destroy(self, resource_id: str, meta: dict) -> None:
        import boto3
        from botocore.exceptions import ClientError

        ec2 = boto3.client("ec2", region_name=meta["region"])
        try:
            ec2.terminate_instances(InstanceIds=[resource_id])
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
                raise

    def _ensure_security_group(self, ec2) -> str:
        from botocore.exceptions import ClientError

        groups = ec2.describe_security_groups(
            Filters=[{"Name": "group-name", "Values": [SECURITY_GROUP]}]
        )["SecurityGroups"]
        if groups:
            sg_id = groups[0]["GroupId"]
        else:
            sg_id = ec2.create_security_group(
                GroupName=SECURITY_GROUP,
                Description="Zeon routing server inbound",
            )["GroupId"]
        # Re-assert ingress every time (duplicates are swallowed) so groups
        # created before TURN existed grow the UDP rules on the next provision.
        for permission in [
            {
                "IpProtocol": "tcp",
                "FromPort": SERVER_PORT,
                "ToPort": SERVER_PORT,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            },
            {
                "IpProtocol": "udp",
                "FromPort": TURN_PORT,
                "ToPort": TURN_PORT,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            },
            {
                "IpProtocol": "udp",
                "FromPort": TURN_RELAY_PORTS[0],
                "ToPort": TURN_RELAY_PORTS[1],
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            },
        ]:
            try:
                ec2.authorize_security_group_ingress(
                    GroupId=sg_id, IpPermissions=[permission]
                )
            except ClientError as e:
                if e.response["Error"]["Code"] != "InvalidPermission.Duplicate":
                    raise
        return sg_id

    def _wait_public_ip(self, ec2, instance_id: str, timeout: int = 120) -> str:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            desc = ec2.describe_instances(InstanceIds=[instance_id])
            inst = desc["Reservations"][0]["Instances"][0]
            ip = inst.get("PublicIpAddress")
            if ip:
                return ip
            time.sleep(3)
        raise ProviderError(f"instance {instance_id} never received a public IP")
