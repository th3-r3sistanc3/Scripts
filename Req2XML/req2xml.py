# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener
from java.io import PrintWriter
import json

class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Any Request to XML Auto Sender (200 Only)")

        self.stdout = PrintWriter(callbacks.getStdout(), True)
        callbacks.registerHttpListener(self)
        self.stdout.println("[*] Any Request → XML Auto Sender (200 Only) loaded.")
        return

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            return

        request_info = self._helpers.analyzeRequest(messageInfo)
        headers = list(request_info.getHeaders())

        # Skip requests sent by this extension itself (to avoid infinite loop)
        for h in headers:
            if h.lower() == "x-from-burpext: 1":
                return

        body_bytes = messageInfo.getRequest()[request_info.getBodyOffset():]
        body_str = body_bytes.tostring().strip()

        if not body_str:
            return

        # Try to parse JSON, else treat as raw string
        try:
            json_data = json.loads(body_str)
            xml_data = self.json_to_xml(json_data)
        except Exception:
            # Wrap raw text inside a <data> tag and escape XML special chars
            safe_body = self.escape_xml(body_str)
            xml_data = "<root><data>%s</data></root>" % safe_body

        # Build new headers with Content-Type: application/xml and marker header
        new_headers = []
        content_type_replaced = False
        for h in headers:
            if h.lower().startswith("content-type"):
                new_headers.append("Content-Type: application/xml")
                content_type_replaced = True
            else:
                new_headers.append(h)
        if not content_type_replaced:
            new_headers.append("Content-Type: application/xml")

        # Add custom header to mark this request as sent by the extension
        new_headers.append("X-From-BurpExt: 1")

        new_body = xml_data.encode("utf-8")
        new_request = self._helpers.buildHttpMessage(new_headers, new_body)

        # Send XML request
        http_service = messageInfo.getHttpService()
        response_info = self._callbacks.makeHttpRequest(http_service, new_request)

        analyzed_response = self._helpers.analyzeResponse(response_info.getResponse())
        status_code = analyzed_response.getStatusCode()

        if status_code == 200:
            self.stdout.println("\n[+] HTTP 200 from: %s" % request_info.getUrl())
            self.stdout.println("[Request - XML Body]")
            self.stdout.println(xml_data)
            self.stdout.println("[Response]")
            resp_body = response_info.getResponse()[analyzed_response.getBodyOffset():].tostring()
            self.stdout.println(resp_body)

    def json_to_xml(self, json_obj, root_tag="root"):
        xml_str = "<%s>" % root_tag
        xml_str += self._dict_to_xml(json_obj)
        xml_str += "</%s>" % root_tag
        return xml_str

    def _dict_to_xml(self, obj):
        xml_str = ""
        if isinstance(obj, dict):
            for key, value in obj.items():
                xml_str += "<%s>%s</%s>" % (key, self._dict_to_xml(value), key)
        elif isinstance(obj, list):
            for item in obj:
                xml_str += "<item>%s</item>" % self._dict_to_xml(item)
        else:
            xml_str += self.escape_xml(str(obj))
        return xml_str

    def escape_xml(self, text):
        """Escape characters for XML"""
        text = text.replace("&", "&amp;")
        text = text.replace("<", "&lt;")
        text = text.replace(">", "&gt;")
        text = text.replace('"', "&quot;")
        text = text.replace("'", "&apos;")
        return text
