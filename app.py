#!/usr/bin/env python3
import os

from aws_cdk import (
    App,
    Duration,
    Stack,
    aws_lambda,
    aws_events,
    aws_events_targets as events_targets,
    aws_iam
)

from constructs import Construct

class SecurityGroupUpdaterCdkStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        with open("lambda_handler.py", encoding="utf8") as file:
            handler_code = file.read()

        lambda_fn = aws_lambda.Function(
            self, "SecurityGroupUpdaterLambda",
            code=aws_lambda.InlineCode(handler_code),
            handler="index.main",
            timeout=Duration.seconds(180),
            runtime=aws_lambda.Runtime.PYTHON_3_12,
        )

        lambda_fn.add_to_role_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=[
                    'ec2:DescribeSecurityGroups',
                    'ec2:RevokeSecurityGroupIngress',
                    'ec2:AuthorizeSecurityGroupIngress'
                ],
                resources=['*']
            )
        )
        
        # Run every 5 minutes
        rule = aws_events.Rule(self, "SecurityGroupUpdaterRule",
            schedule=aws_events.Schedule.rate(Duration.minutes(5)))
        rule.add_target(events_targets.LambdaFunction(lambda_fn))

app = App()
SecurityGroupUpdaterCdkStack(app, "SecurityGroupUpdater")
app.synth()
