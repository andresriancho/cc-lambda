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
 * `memory` should be `512`

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

The application reads the `input/warc.paths` file and writes to:

 * `processed.paths`: text file containing the WARC paths that were successfully analyzed
 * `failed.paths`: text file containing the WARC paths that failed (most likely because of a lambda timeout reached)

When calling `cc-lambda.py` the script will check if there are any WARC paths
in the input which were not already processed or failed, and go through those.
Remove `processed.paths` and `failed.paths` if you want to re-process all WARC paths.

HTTP responses that match the search are stored in the `MATCH_S3_BUCKET` S3 bucket.

```console
$ python cc-lambda.py 
No handlers could be found for logger "pywren.executor"
Overall progress: 1.55%
Going to process 250 WARC paths
Got futures from map(), waiting for results...

crawl-data/CC-MAIN-2019-09/segments/1550247479101.30/warc/CC-MAIN-20190215183319-20190215205319-00000.warc.gz
  - Time (seconds): 191.205149174
  - Processed pages: 44969
  - Ignored pages: 93005
  - Matches: {'aws_re_matcher': 9, 'cognito_matcher': 4}
```

## Debugging

Remember: [AWS Lambda sends logs to CloudWatch](https://docs.aws.amazon.com/lambda/latest/dg/python-logging.html)
and you can access the logs [here](https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#logs:).

```bash
PYWREN_LOGLEVEL=INFO python cc-lambda.py
```

## Costs

As the Common Crawl dataset lives in the Amazon Public Datasets program, 
you can access and process it without incurring any transfer costs. 

The costs you'll incur by running this software are:

 * Lambda function
 * S3 storage
 
The highest cost will come from AWS lambda. In order to reduce this cost you
should:

 * Improve the lambda function code to run faster
 * Improve the lambda function to use less RAM
 * Search for `Max Memory Used` in the [cloudwatch logs for lambda](https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#logs:)
   and make sure the lambda function configuration is uses ~50mb more of RAM than the max memory used from the log.
 
After running the tool a few times make sure you also run [lambda-cost-calculator](https://github.com/epsagon/lambda-cost-calculator):

```console
+---------------------+-----------+--------------------------+-----------------------------+
| Function            | Region    | Cost in the Last Day ($) | Monthly Cost Estimation ($) |
+---------------------+-----------+--------------------------+-----------------------------+
| pywren_cc_search_v3 | us-east-1 | 6.410                    | 192.296                     |
+---------------------+-----------+--------------------------+-----------------------------+
Total monthly cost estimation: $192.296
```

## Monitoring

It is possible to monitor the progress of the analysis process using the following
[CloudWatch Insights](https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#logs-insights:)
search. 

```
fields @timestamp, @message
| sort @timestamp desc
| filter @message like /total_seen/
```

Make sure you choose the right lambda function from the drop-down!