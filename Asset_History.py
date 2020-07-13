# Asset Discover: Burp Suite Extension to find related assets (domain, IP, S3 Buckets etc.) from a webpage. #AssetDiscovery
# By: RedHunt Labs (www.redhuntlabs.com)
# Twitter: https://twitter.com/redhuntlabs

# Code Credits:
# OpenSecurityResearch CustomPassiveScanner: https://github.com/OpenSecurityResearch/CustomPassiveScanner
# PortSwigger example-scanner-checks: https://github.com/PortSwigger/example-scanner-checks

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array
import re
import urllib2
import json
# Implement BurpExtender to inherit from multiple base classes
# IBurpExtender is the base class required for all extensions
# IScannerCheck lets us register our extension with Burp as a custom scanner check
class BurpExtender(IBurpExtender, IScannerCheck):

    scopedomains = []

    # The only method of the IBurpExtender interface.
    # This method is invoked when the extension is loaded and registers
    # an instance of the IBurpExtenderCallbacks interface
    def	registerExtenderCallbacks(self, callbacks):
        # Put the callbacks parameter into a class variable so we have class-level scope
        self._callbacks = callbacks

        # Set the name of our extension, which will appear in the Extender tool when loaded
        self._callbacks.setExtensionName("Asset History")

        # Register our extension as a custom scanner check, so Burp will use this extension
        # to perform active or passive scanning and report on scan issues returned
        self._callbacks.registerScannerCheck(self)

        return

    # This method is called when multiple issues are reported for the same URL
    # In this case we are checking if the issue detail is different, as the
    # issues from our scans include affected parameters/values in the detail,
    # which we will want to report as unique issue instances
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if (existingIssue.getIssueDetail() == newIssue.getIssueDetail()):
            return -1
        else:
            return 0

    # Implement the doPassiveScan method of IScannerCheck interface
    # Burp Scanner invokes this method for each base request/response that is passively scanned.
    def doPassiveScan(self, baseRequestResponse):
        # Local variables used to store a list of ScanIssue objects
        scan_issues = []
        tmp_issues = []


        # Call the findRegEx method of our CustomScans object to check
        # the response for anything matching a specified regular expression
        # This one matches an IP
        issuename = "Asset History: URL"
        issuelevel = "Information"
        issuedetail = "Historic URLs Discovered: <b>$asset$</b>"

        # Get an instance of IHelpers, which has lots of useful methods, as a class
        # variable, so we have class-level scope to all the helper methods
        self._helpers = self._callbacks.getHelpers()

        self._requestResponse = baseRequestResponse

        # Finally, per the interface contract, doPassiveScan needs to return a
        # list of scan issues, if any, and None otherwise
        if self._callbacks.isInScope(self._helpers.analyzeRequest(self._requestResponse).getUrl()):
            url = self._helpers.analyzeRequest(self._requestResponse).getUrl()
            domain = str(url).split("//")[-1].split(":")[0].split('?')[0]
            global scopedomains
            scopedomains = self.scopedomains
            print scopedomains
            if domain not in scopedomains:
              print "Target Domain: "+domain
              url = "http://web.archive.org/cdx/search/cdx?url=/"+domain+"/*&output=json"
              print url
              try:
                scopedomains.append(domain)
                webarchive = urllib2.urlopen(url)
                webarchivejson = json.load(webarchive)
                print webarchivejson
                urls = []
                for wa in webarchivejson:
                  urls.append(wa[2])
                if urls:
                  urls.pop(0)
                uniqueurl = '<li>'+'</li>\r\n<li>'.join(set(urls))
                print "URLs Discovered:"
                for url in set(urls):
                  print url
            # Create a ScanIssue object and append it to our list of issues, marking
            # the matched value in the response.
                if uniqueurl:
                  scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                  self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                  [self._callbacks.applyMarkers(self._requestResponse, None, None)],
                  issuename, issuelevel, issuedetail.replace("$asset$", uniqueurl)))
              except:
                  print("Exception Occured")
                  scopedomains.pop()




        if len(scan_issues) > 0:
            return scan_issues
        else:
            return None



# Implementation of the IScanIssue interface with simple constructor and getter methods
class ScanIssue(IScanIssue):
    def __init__(self, httpservice, url, requestresponsearray, name, severity, detailmsg):
        self._url = url
        self._httpservice = httpservice
        self._requestresponsearray = requestresponsearray
        self._name = name
        self._severity = severity
        self._detailmsg = detailmsg

    def getUrl(self):
        return self._url

    def getHttpMessages(self):
        return self._requestresponsearray

    def getHttpService(self):
        return self._httpservice

    def getRemediationDetail(self):
        return None

    def getIssueDetail(self):
        return self._detailmsg

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueType(self):
        return 0

    def getIssueName(self):
        return self._name

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Tentative"
