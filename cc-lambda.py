from __future__ import print_function

import os
import re
import logging
import time
import json
import datetime
import base64
import hashlib
import zlib
import codecs

import boto3
import pywren
import sentry_sdk

from warcio.archiveiterator import ArchiveIterator

MATCH_S3_BUCKET = 'common-crawl-aws-js-sdk'
MATCH_S3_PATH = 'matches'

WARC_PATH_FILE = 'input/warc.paths'
PROCESSED_WARC_PATHS = 'processed.paths'
FAILED_WARC_PATHS = 'failed.paths'
MAX_PATHS_PER_RUN = 1

#
# Applying regular expressions to all pages on the internet takes considerable
# time, and in most cases it makes no sense when trying to identify a statistically
# significant sample set
#
# Set MAX_PAGES_PER_DOMAIN to limit the number of pages we'll analyze for each
# domain. The cache is kept in DynamoDB
#
MAX_PAGES_PER_DOMAIN = 100

REPORT_STATUS_EVERY = 5000

#
# The search string order is important because after the first string matches
# in the HTTP response body, the tool will stop matching and saving results.
#
# You want to add the strings which are more specific to your research on top
# and the least specific below.
#
SEARCH_STRINGS = [
    'IdentityPoolId',                   # a4ff6b9b40d16573a7dac372b601bd2c
    'AWS.CognitoIdentityCredentials(',  # 2309dcd83538c36192b043d6f5ab8704
    'AWS.WebIdentityCredentials(',      # ff3b6fda16006fd516c94f18ccdacd38
    'assumeRoleWithWebIdentity',        # 946047774e119e9b4f38189d57b72c31
    'sdk.amazonaws.com/js/aws-sdk',     # 723ef23b97462a594cd08bc6090130cd
    'AWS.config.update',                # 3ce50e87de0c4e1a00fbb9fd29c0913e
    "from 'aws-amplify';",              # be91c8d26b24ce9c0832cf483c3cb94f
    "require('aws-sdk');",              # fae45b68fb137e5a4828df2bdb4a9d72
]

PROCESS_MIME_TYPES = {
    'text/html',
    'text/javascript',
    'text/ecmascript',
    'application/javascript',
    'application/ecmascript',
}

IGNORE_MIME_TYPES = {
    'text/css',
    'text/csv',
    'text/calendar',
    'text/cache-manifest',
    'text/v-card',
    'text/vtt',
    'text/x-component',
}

#
# https://summitroute.com/blog/2018/06/20/aws_security_credential_formats/
#
# Prefixes: ASIA, AKIA, AIDA, AROA
#
# Example: ASIAJLVYNHUWCPKOPSYQ
#
#   The 5th letter is always I or J
#   The last letter is always A or Q
#
AWS_KEY_RE = re.compile('(\'|")(ASIA|AKIA|AIDA|AROA)(J|I)[A-Z0-9]{14}(A|Q)(\'|")')

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def should_process_record(record):
    #
    # WARC records have three different types:
    #
    #   "application/warc-fields"
    #   "application/http; msgtype=request"
    #   "application/http; msgtype=response"
    #
    # We're only interested in the HTTP responses
    #
    if record.rec_type != 'response':
        return False, None

    body = record.content_stream().read()

    #
    # We're only interested in the text HTTP responses, and we're not
    # interested in CSS files
    #
    # The get_header() does a case insensitive search
    #
    content_type = record.http_headers.get_header('content-type', default_value=None)

    # There is no content-type in the response, ignore
    if content_type is None:
        return False, None

    should_process = False

    for mime_type in PROCESS_MIME_TYPES:
        if mime_type in content_type:
            should_process = True
            break

    if not should_process:
        url = record.rec_headers.get_header('WARC-Target-URI')

        msg = 'Ignored %s due to mime type filter'
        args = (url,)
        logger.info(msg % args)

        return False, None

    return True, (record.http_headers, body)


def process_record(warc_path, record, headers, body, match_stats):
    for matcher in [aws_re_matcher, cognito_matcher]:
        match_count = matcher(warc_path, record, headers, body)

        if match_count:
            if matcher.__name__ in match_stats:
                match_stats[matcher.__name__] += match_count
            else:
                match_stats[matcher.__name__] = match_count


def aws_re_matcher(warc_path, record, headers, body):
    mo = AWS_KEY_RE.search(body)

    if mo is None:
        return 0

    aws_access_key = mo.group(0)
    save_match_to_s3(warc_path, record, headers, body, aws_access_key)
    return 1


def cognito_matcher(warc_path, record, headers, body):
    for search_string in SEARCH_STRINGS:
        if search_string in body:
            save_match_to_s3(warc_path, record, headers, body, search_string)
            return 1

    return 0


def save_match_to_s3(warc_path, record, headers, body, search_string):
    url = record.rec_headers.get_header('WARC-Target-URI')
    ip_address = record.rec_headers.get_header('WARC-IP-Address')
    date = record.rec_headers.get_header('WARC-Date')

    # headers is an instance of StatusAndHeaders defined in statusandheaders.py
    headers_str = headers.to_ascii_bytes()

    match = dict()
    match['search_string'] = search_string
    match['ip_address'] = ip_address
    match['date'] = date
    match['headers'] = b64_encode(headers_str)
    match['body'] = b64_encode(body)
    match['url'] = b64_encode(url)

    search_string_hash = md5_hash(search_string)
    payload_hash = md5_hash(body)

    key = '%s-%s.json.gz' % (search_string_hash, payload_hash)

    data = to_json_string(match)
    data = zlib.compress(data, 8)

    segment = get_segment_from_line(warc_path)

    s3 = boto3.resource('s3')
    s3_object = s3.Object(MATCH_S3_BUCKET, '%s/%s/%s' % (MATCH_S3_PATH, segment, key))
    s3_object.put(Body=data)


def get_segment_from_line(line):
    # Input will look like: crawl-data/CC-MAIN-2019-09/segments/1550247479101.30/warc/CC-MAIN-20190215183319-20190215205319-00033.warc.gz
    # Output is: 00000
    return line.rsplit('-', 1)[1].split('.')[0]


def b64_encode(data):
    return base64.b64encode(data)


def to_json_string(data):
    data_str = json.dumps(data,
                          indent=4,
                          sort_keys=True,
                          default=json_encoder,
                          encoding='UTF-8')
    return data_str


def json_encoder(o):
    if type(o) is datetime.date or type(o) is datetime.datetime:
        return o.isoformat()


def md5_hash(data):
    m = hashlib.md5()
    m.update(data)
    return m.hexdigest()


def process_warc_archive(warc_path):
    sentry_sdk.init("https://1f99fe891d904df8b29db12358b72694@sentry.io/1409316")

    start = time.time()
    processed_records = 0
    ignored_records = 0
    match_stats = dict()

    s3 = boto3.client('s3')
    obj = s3.get_object(Bucket='commoncrawl',
                        Key='commoncrawl/%s' % warc_path)
    body = obj['Body']

    warc_file = codecs.getreader('utf-8')(body)

    for i, record in enumerate(ArchiveIterator(warc_file, arc2warc=True)):
        _should_process_record, data = should_process_record(record)
        if not _should_process_record:
            ignored_records += 1
            continue

        headers, body = data
        process_record(warc_path, record, headers, body, match_stats)
        processed_records += 1

        if i % REPORT_STATUS_EVERY == 0:
            report_status(i, start, processed_records, ignored_records, warc_path)

    spent = time.time() - start
    return warc_path, spent, processed_records, ignored_records, match_stats


def report_status(num_records, start, processed_records, ignored_records, warc_path):
    segment = get_segment_from_line(warc_path)

    spent_time = time.time() - start
    records_per_second = float(processed_records) / spent_time

    data = {
        'processed': processed_records,
        'total_seen': num_records,
        'ignored': ignored_records,
        'segment': segment,
        'processing_speed': records_per_second,
    }

    message = json.dumps(data)
    print(message)


def get_warc_paths():
    warc_paths = []

    for line in file(WARC_PATH_FILE):
        line = line.strip()
        warc_paths.append(line)

    return warc_paths


def is_already_processed_warc_path(warc_path):
    if not os.path.exists(PROCESSED_WARC_PATHS):
        return False

    for line in file(PROCESSED_WARC_PATHS):
        line = line.strip()
        if line == warc_path:
            return True


def record_processed_warc_path(warc_path):
    if not is_already_processed_warc_path(warc_path):
        file(PROCESSED_WARC_PATHS, 'a').write('%s\n' % warc_path)


def get_processed_warc_paths():
    warc_paths = []

    for line in file(PROCESSED_WARC_PATHS):
        line = line.strip()
        warc_paths.append(line)

    return warc_paths


def get_failed_warc_paths():
    warc_paths = []

    for line in file(FAILED_WARC_PATHS):
        line = line.strip()
        warc_paths.append(line)

    return warc_paths


def is_failed_warc_path(warc_path):
    if not os.path.exists(FAILED_WARC_PATHS):
        return False

    for line in file(FAILED_WARC_PATHS):
        line = line.strip()
        if line == warc_path:
            return True


def record_failed_warc_path(warc_path):
    if not is_failed_warc_path(warc_path):
        file(FAILED_WARC_PATHS, 'a').write('%s\n' % warc_path)


def handle_result(result, completed_warc_paths):
    warc_path, spent, processed_records, ignored_records, match_stats = result

    if warc_path not in completed_warc_paths:

        completed_warc_paths.add(warc_path)
        record_processed_warc_path(warc_path)

        print('')
        print(warc_path)
        print('  - Time (seconds): %.2f' % spent)
        print('  - Processed pages: %s' % processed_records)
        print('  - Ignored pages: %s' % ignored_records)
        print('  - Matches: %r' % match_stats)
        print('')


def handle_timeout(future, failed_warc_paths):
    if future not in failed_warc_paths:
        failed_warc_paths.add(future)

        print('A future timed out!')


def handle_generic_failure(future, failed_warc_paths, exc):
    if future not in failed_warc_paths:
        failed_warc_paths.add(future)

        print('A future failed with error: %s' % exc)


def main():
    start = time.time()
    wren_exec = pywren.default_executor(job_max_runtime=850)

    all_warc_paths = get_warc_paths()
    processed_warc_paths = get_processed_warc_paths()
    failed_warc_paths = get_failed_warc_paths()

    progress = float(len(processed_warc_paths) + len(failed_warc_paths)) / len(all_warc_paths)
    print('')
    print('Overall progress: %.2f%%' % (progress * 100,))
    print('')

    pending_warc_paths = [wp for wp in all_warc_paths if wp not in processed_warc_paths]
    pending_warc_paths = [wp for wp in pending_warc_paths if wp not in failed_warc_paths]
    pending_warc_paths = pending_warc_paths[:MAX_PATHS_PER_RUN]

    completed_warc_paths = set()
    failed_warc_paths = set()

    print('Going to process %s WARC paths' % len(pending_warc_paths))

    futures = wren_exec.map(process_warc_archive, pending_warc_paths)

    print('Got futures from map(), waiting for results...')

    # Force the first while loop run
    incomplete_futures = [1]

    while incomplete_futures:

        try:
            completed_futures, incomplete_futures = pywren.wait(futures, return_when=pywren.ANY_COMPLETED)
        except Exception, e:
            exception_message = str(e)
            failed_to_connect_to_s3 = 'Could not connect to the endpoint URL'

            if failed_to_connect_to_s3 in exception_message:
                time.sleep(1)
                continue

            raise

        for future in completed_futures:
            try:
                result = future.result(storage_handler=wren_exec.storage)
            except Exception, e:
                # This is ugly but they are raising Exception (not a subclass)
                run_out_of_time = 'process ran out of time'
                current_exception_msg = str(e)

                if run_out_of_time in current_exception_msg:
                    handle_timeout(future, failed_warc_paths)
                else:
                    handle_generic_failure(future, failed_warc_paths, e)
            else:
                handle_result(result, completed_warc_paths)

    #
    # The future object has no reference to the parameters :facepalm:
    # so we have to find out which warc_paths failed by doing a set -
    # between pending and completed
    #
    pending_warc_paths = set(pending_warc_paths)
    failed_warc_paths = pending_warc_paths - completed_warc_paths

    for failed_warc in failed_warc_paths:
        record_failed_warc_path(failed_warc)

    if failed_warc_paths:
        print('%s WARC files failed' % len(failed_warc_paths))

    spent = time.time() - start
    print('Spent %.2f wall clock seconds' % spent)


if __name__ == '__main__':
    main()
