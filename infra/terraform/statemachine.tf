# The rollout workflow. STANDARD (Express is not free) and no logging
# configuration: CloudWatch Logs for Step Functions would cost money, and the
# rollout record plus the Lambda logs already tell the story.

data "aws_iam_policy_document" "states_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

data "aws_iam_policy_document" "states" {
  statement {
    sid       = "InvokeWorkerOnly"
    effect    = "Allow"
    actions   = ["lambda:InvokeFunction"]
    resources = [aws_lambda_function.worker.arn, "${aws_lambda_function.worker.arn}:*"]
  }
}

resource "aws_iam_role" "states" {
  name               = "iamap-rollout-states-role"
  description        = "Lets the rollout state machine invoke iamap-worker."
  assume_role_policy = data.aws_iam_policy_document.states_trust.json
}

resource "aws_iam_role_policy" "states" {
  name   = "iamap-invoke-worker"
  role   = aws_iam_role.states.id
  policy = data.aws_iam_policy_document.states.json
}

resource "aws_sfn_state_machine" "rollout" {
  name     = "iamap-rollout"
  type     = "STANDARD"
  role_arn = aws_iam_role.states.arn
  definition = templatefile("${path.module}/../../statemachine/rollout.asl.json", {
    worker_arn = aws_lambda_function.worker.arn
  })
}
