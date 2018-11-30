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

        self.grep_file_extensions = ["js", "jsp", "json", ".jspx"]
        self.possibleContentTypes = ["application/javascript", "application/ecmascript", "application/jscript", "application/json"]
        self.ichars = ['{', '<']

    def _get_matches(self, response, match):
        matches = []
        start = 0
        reslen = len(response)
        matchlen = len(match)
        if self.isScript(response) == True:
        	matches.append(array('i', [start, start + matchlen]))
	        while start < reslen:
	            start = self._helpers.indexOf(response, match, False, start, reslen)
	            if start == -1:
	                break
	            start += matchlen

        return matches

    def doPassiveScan(self, baseRequestResponse):
    	
    	issues = []

    	matches = []

    	for ex in self.grep_file_extensions:
    		matches = self._get_matches(baseRequestResponse.getResponse(), self._helpers.stringToBytes(ex))

    		if len(matches) > 0:
    			issues.append(CustomScanIssue(
		            baseRequestResponse.getHttpService(),
		            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
		            [self._callbacks.applyMarkers(baseRequestResponse, None, matches)],
		            "JavaScript file found",
		            "The following javascript file was found: " + ex,
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
        fileEnding = ".totallynotit"
        urlSplit = str(url).split("/")
        if len(urlSplit) != 0:
            fileName = urlSplit[len(urlSplit) - 1]
            fileNameSplit = fileName.split(".")
            fileEnding = fileNameSplit[len(fileNameSplit) - 1]
            fileEnding = fileEnding.split("?")[0]
        return any(fileEnd in fileEnding for fileEnd in self.grep_file_extensions)

    def hasScriptContentType(self, response):
        """ Checks for common content types, that could be scripts """
        responseInfo = self._helpers.analyzeResponse(response)
        headers = responseInfo.getHeaders()
        contentType = ""
        contentTypeL = [x for x in headers if "content-type:" in x.lower()]
        if len(contentTypeL) == 1:
            contentType = contentTypeL[0].lower()
        return any(content in contentType for content in self.possibleContentTypes)

    def isScript(self, requestResponse):
        """Determine if the response is a script"""
        try:
            response = requestResponse
        except:
            return False
        if not self.hasBody(response):
            return False
        responseInfo = self._helpers.analyzeResponse(response)
        body = response.tostring()[responseInfo.getBodyOffset():]
        first_char = body[0:1]
        mimeType = responseInfo.getStatedMimeType().split(';')[0]
        inferredMimeType = responseInfo.getInferredMimeType().split(';')[0]
        return (first_char not in self.ichars and
                ("script" in mimeType or "script" in inferredMimeType or
                 self.hasScriptFileEnding(requestResponse) or self.hasScriptContentType(response)))

    def hasBody(self, response):
        """
        Checks whether the response contains a body
        """
        responseInfo = self._helpers.analyzeResponse(response)
        body = response[responseInfo.getBodyOffset():]
        return len(body) > 0



class CustomScanIssue (IScanIssue):
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