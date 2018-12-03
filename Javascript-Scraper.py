from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array


class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("JavaScript Scraper")
        callbacks.registerScannerCheck(self)

        self.grep_file_extensions = ["js", "jsp", "json", "jspx"]

    def _get_matches(self, response):
        matches = []
        start = 0
        match = self.isScript(response)
        print(match)
        reslen = len(response)
        matchlen = len(match)
        while start < reslen:
            start = self._helpers.indexOf(response, match, False, start, reslen)
            if start == -1:
                break
            matches.append(array('i', [start, start + matchlen]))
            start += matchlen

        return matches

    def doPassiveScan(self, baseRequestResponse):
        issues = []
        matches = self._get_matches(baseRequestResponse.getResponse())
        if len(matches) > 0:
            issues.append(CustomScanIssue(
                baseRequestResponse.getHttpService(),
                self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                [self._callbacks.applyMarkers(baseRequestResponse, None, matches)],
                "JavaScript file found",
                "The following Javascript file was found :",
                "Information"))

        if (len(issues) == 0):
            return None

        return issues

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1

        return 0

    def hasScriptFileEnding(self, requestResponse):
        """
        Checks for common script file endings
        """
        url = self._helpers.analyzeRequest(requestResponse).getUrl()
        urlSplit = str(url).split("/")
        if len(urlSplit) != 0:
            fileName = urlSplit[len(urlSplit) - 1]
            fileNameSplit = fileName.split(".")
            fileEnding = fileNameSplit[len(fileNameSplit) - 1]
            fileEnding = fileEnding.split("?")[0]
            for fileEnd in fileEnding:
                if fileEnd in self.grep_file_extensions:
                    print("hasScriptFileEnding" + fileEnd)
                    return fileEnd

    def hasScriptContentType(self, response):
        """ Checks for common content types, that could be scripts """
        responseInfo = self._helpers.analyzeResponse(response)
        headers = responseInfo.getHeaders()
        contentType = ""
        contentTypeL = [x for x in headers if "content-type:" in x.lower()]
        if len(contentTypeL) == 1:
            contentType = contentTypeL[0].lower()
        for content in contentType:
            if content in self.possibleContentTypes:
                print("hasScriptContentType = " + content)
                return content

    def isScript(self, requestResponse):
        """Determine if the response is a script"""
        try:
            response = requestResponse
        except:
            return False
        if not self.hasBody(response):
            return False
        responseInfo = self._helpers.analyzeResponse(response)
        mimeType = responseInfo.getStatedMimeType().split(';')[0]
        inferredMimeType = responseInfo.getInferredMimeType().split(';')[0]
        if "script" in mimeType:
            return responseInfo.getStatedMimeType()
        elif "script" in inferredMimeType:
            return responseInfo.getInferredMimeType()
        elif self.hasScriptFileEnding(requestResponse) is not None:
            return self.hasScriptFileEnding(requestResponse)
        elif self.hasScriptContentType(response) is not None:
            return self.hasScriptContentType(response)
        else:
            return False

    def hasBody(self, response):
        """
        Checks whether the response contains a body
        """
        responseInfo = self._helpers.analyzeResponse(response)
        body = response[responseInfo.getBodyOffset():]
        return len(body) > 0


class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
