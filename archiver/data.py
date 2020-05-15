import re


# ADJUSTED_FLOWS = [
#     # Content type
#     {
#         'match_type': 'content_type',
#         'adjustment_method': 'strip_content_response',
#         'match_value': re.compile('image/.*'),
#     },
#     {
#         'match_type': 'content_type',
#         'adjustment_method': 'strip_content_response',
#         'match_value': re.compile('audio/.*'),
#     },
#     {
#         'match_type': 'content_type',
#         'adjustment_method': 'strip_content_response',
#         'match_value': re.compile('video/.*'),
#     },
# ]


INVALID_REQUESTS = [
    # Testing requests
    {
        'match_type': 'url',
        'match_value': re.compile('(127\.0\.0\.1|localhost):[0-9]{4}(?!/auto-crawl/test-|/auto-crawl/update-)'),
    },
    {
        'match_type': 'url',
        'match_value': re.compile('(127\.0\.0\.1|localhost)(?!/auto-crawl/test-|/auto-crawl/update-)'),
    },
    # Remote control requests
    {
        'match_type': 'host',
        'match_value': re.compile('0cab400a183048a6a995a6fefeff3795\.com$'),
    },
    {
        'match_type': 'host',
        'match_value': re.compile('f9730d272bff468eb2c027e6d4dcf81f\.com$'),
    },
    # Injected requests
    {
        'match_type': 'path',
        'match_value': re.compile('/ec8d334e85084245940a97e127a8ff81'),
    },
    {
        'match_type': 'path',
        'match_value': re.compile('/6fc356938f124cc0b23902773f6c495b'),
    },
    {
        'match_type': 'path',
        'match_value': re.compile('/ed761adff5e24dbc93a5b05147161c94'),
    },
    # Slack requests
    {
        'match_type': 'host',
        'match_value': re.compile('slack\.com$'),
    },
    # Office 365 requests
    {
        'match_type': 'host',
        'match_value': re.compile('\.office365\.com$'),
    },
    # Firefox browser requests
    {
        'match_type': 'host',
        'match_value': re.compile('\.mozilla\.net$'),
    },
    {
        'match_type': 'host',
        'match_value': re.compile('\.mozilla\.com$'),
    },
    {
        'match_type': 'host',
        'match_value': re.compile('\.mozilla\.org$'),
    },
    {
        'match_type': 'host',
        'match_value': re.compile('\.firefox\.com$'),
    },
    # LastPass requests
    {
        'match_type': 'host',
        'match_value': re.compile('\.lastpass\.com$')
    },
    # AWS requests
    {
        'match_type': 'host',
        'match_value': re.compile('\.aws\.amazon\.com$')
    }
]
