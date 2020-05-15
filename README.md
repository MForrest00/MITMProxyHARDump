### MITM Proxy HAR Dump

Man in the middle proxy designed to flag a page load based upon the presence of one or more instances of text in the request/response flow (signatures) OR upon the detection of an unplanned page load.  
In either event, a HAR file will be dumped to an S3 bucket. In the event of an unplanned page load, a screenshot will be taken of the page and dumped to an S3 bucket.  
In order to screenshot functionality to work, the proxy must have access to an html2canvas proxy to load unsafe assets (see: <https://github.com/niklasvh/html2canvas-proxy-nodejs>).
This application MUST be hosted within a Kubernetes cluster. It must also have access to an S3 bucket.  
This application is tightly coupled with a webserver which provides a frontend for managing and monitoring the proxies.

#### Environment Variables

+ Required:
    + `AWS_ACCESS_KEY_ID` - AWS access key (see: <https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html>)
    + `AWS_SECRET_ACCESS_KEY` - AWS secret key (see: <https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html>)
+ Optional:
    + `MITM_PROXY_AUTO_CRAWL_SCHEME` - scheme for the webserver frontend (defaults to `http`)
    + `MITM_PROXY_AUTO_CRAWL_HOST` - host for the webserver frontend (defaults to `MITM_PROXY_AUTO_CRAWL_HOST`)
    + `HTML2CANVAS_PROXY_SCHEME` - scheme for the webserver frontend (defaults to `http`)
    + `HTML2CANVAS_PROXY_HOST` - host for the webserver frontend (defaults to `MITM_PROXY_AUTO_CRAWL_HOST`)
