This Burp Suite extension automatically intercepts all outgoing HTTP requests that contain a body, converts their payloads into XML format, and sends the converted XML request to the original target server. The script handles both JSON and non-JSON request bodies:

- If the original request body is valid JSON, it converts the JSON data to a structured XML representation.
- If the request body is not JSON, it wraps the raw data inside XML tags while properly escaping XML special characters.

To avoid an infinite loop caused by processing its own generated XML requests, the extension adds a custom header (X-From-BurpExt: 1) to each XML request it sends, and skips any request containing this header.
The extension only prints the XML request and its corresponding response if the server returns an HTTP status code 200 OK.

This tool is useful for testing how servers handle XML input when the original request was in JSON or other formats, and for quickly seeing server responses to XML payloads without manually converting requests.sa
