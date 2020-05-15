### MITM Proxy HAR Dump

+ This is a man in the middle proxy designed to flag a page load based upon the presence of one or more instances of text in the response (signatures) OR upon the detection of an unplanned page load.
+ In either event, a HAR file will be dumped to an S3 bucket. In the event of an unplanned page load, a screenshot will be taken of the page and dumped to an S3 bucket.
+ In order for the screenshot functionality to work, the proxy must have access to an html2canvas proxy server to load unsafe assets (see: <https://github.com/niklasvh/html2canvas-proxy-nodejs>).
+ This application MUST be hosted within a Kubernetes cluster. It must also have access to an S3 bucket.
+ This application is tightly coupled with a webserver which provides a frontend for managing and monitoring the proxies.


#### Environment Variables

+ Required:
    + `AWS_ACCESS_KEY_ID` - AWS access key (see: <https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html>)
    + `AWS_SECRET_ACCESS_KEY` - AWS secret key (see: <https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html>)
+ Optional:
    + `MITM_PROXY_AUTO_CRAWL_SCHEME` - scheme for the webserver frontend (defaults to `http`)
    + `MITM_PROXY_AUTO_CRAWL_HOST` - host for the webserver frontend (defaults to `127.0.0.1:8000`)
    + `HTML2CANVAS_PROXY_SCHEME` - scheme for the webserver frontend (defaults to `http`)
    + `HTML2CANVAS_PROXY_HOST` - host for the webserver frontend (defaults to `127.0.0.1:3000`)
    + `MITM_SIGNATURES_BUCKET` - S3 bucket where signatures are hosted (defaults to `mitm-signatures`)
    + `MITM_SIGNATURES_FILE` - JSON file in which signatures are hosted (defaults to `signatures.json`)
    + `MITM_OUTPUT_BUCKET` - S3 bucket to dump output to (defaults to `mitm-archive`)
    + `MITM_PROXY_KUBERNETES_NAMESPACE` - Kubernetes namespace for the proxy (defaults to `default`)
    + `MITM_PROXY_KUBERNETES_SERVICE_NAME` - Kubernetes service name for the proxy (if not present, will attempt to retrieve from the `HOSTNAME` environment variable automatically set within the node)


#### Data Module

The data module in the archiver package provides some configuration on which requests and responses are recorded, and what components of the request and response are recorded.

+ `ADJUSTED_FLOWS`
    + In some scenarios, you may want to avoid saving the content of the request and/or response in order to save on storage space. For example, you may not care about the response content for image requests. This object enables this functionality.
    + Each dictionary in the list represents a scenario where you would want to avoid saving some content. Keys in the dictionary are:
        + `match_type` - which element of the request/response you are matching against (possible values are `host`, `path`, `url`, or `content_type`)
        + `match_value` - regular expression to use for the match
        + `adjustment_method` - how you want to modify the HAR dump in the event of a match (possible values are `strip_content_request`, `strip_content_response`, or `strip_content_both`)
+ `INVALID_REQUESTS`
    + For some requests, you may want to fully ignore that the request and response occurred. For example, you may want to avoid Firefox browser requests to Mozilla, as they are not relevant to your testing. This object enables this functionality.
    + Each dictionary in the list represents a scenario where you would want to fully ignore the request and response. Keys in the dictionary are:
        + `match_type` - which element of the request you are matching against (possible values are `host`, `path`, and `url`)
        + `match_value` - regular expression to use for the match


#### Signatures

+ Signatures represent the presence of a text element in the response which flags the flow for a HAR file dump.
+ Signatures are retrieved from a JSON file in an S3 bucket on the initiation of any planned page load.
+ The JSON file should contain a key `signatures` with a value of a list.
+ Each element in the list should be an object with the following keys:
    + `signature_id` - an integer ID of the signature
    + `match_type` - which element of the response you are matching against (possible values are `host`, `path`, `url`, or `response_content`)
    + `match_value` - regular expression to use for the match
    + `date_created` - date and time at which the signature was created