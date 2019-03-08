![Common Crawl Logo](http://commoncrawl.org/wp-content/uploads/2016/12/logocommoncrawl.png)

## Cognito Common Crawl

This program uses [pywren](http://pywren.io) to search [common crawl](http://commoncrawl.org) 

## Setup

```bash
virtualenv env/
source env/bin/activate
pip install -r requirements.txt
```

Set your AWS credentials as `[default]` in `~/.aws/credentials` and make sure your
default region is set to `us-east-1`.

Then configure `pywren`:

```bash
pywren get_aws_account_id
pywren create_config --force
```

Edit the `~/.pywren_config` file and specify:

 * `aws_region` should be `us-east-1`
 * `bucket` should be unique bucket name
 * `memory` should be `1200`

```bash
pywren create_bucket
pywren create_role
pywren deploy_lambda
```

Confirm that everything is working using `pywren test_function`

## Configuration

Change the following in `cc-lambda.py`:

 * `MATCH_S3_BUCKET`: the bucket where you want to store your findings
 * `sentry_sdk.init("...")`: should either be removed or changed to your sentry ID

## Running the application

Application runs will spawn multiple lambda functions that analyze common crawl
WARC files at scale. Running this function will have an impact on your AWS billing!

The application reads the `input/warc.paths` file and writes the processed WARC
paths to `processed.paths`. When calling `cc-lambda.py` the script will check if
there are any WARC paths in the input which were not already processed, and go
through those. Remove `processed.paths` if you want to re-process all WARC paths.

HTTP responses that match the search are stored in the `MATCH_S3_BUCKET` S3 bucket.

## Debugging

Remember: [AWS Lambda sends logs to CloudWatch](https://docs.aws.amazon.com/lambda/latest/dg/python-logging.html)
and you can access the logs [here](https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#logs:).

### Costs

As the Common Crawl dataset lives in the Amazon Public Datasets program, 
you can access and process it without incurring any transfer costs. 

The costs you'll incur by running this software are:

 * Lambda function
 * S3 storage
 * DynamoDB
