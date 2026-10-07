"""Small XML adapter for the tenant's Classic API, using the same OAuth token."""
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

from upload import Jamf


class ClassicJamf(Jamf):
    def classic(self, method, resource, body=None, missing_ok=False):
        if resource.split("/", 1)[0] not in {"policies", "scripts", "computergroups"}:
            raise ValueError("Unexpected Classic API resource")
        if method not in {"GET", "POST", "PUT"}:
            raise ValueError("Unsupported Classic API operation")
        data = ET.tostring(body, encoding="utf-8") if body is not None else None
        request = urllib.request.Request(
            self.url + "/JSSResource/" + resource, data=data, method=method,
            headers={"Authorization": f"Bearer {self.token}",
                     "Accept": "application/xml", "Content-Type": "application/xml"})
        try:
            with self.opener.open(request, timeout=120) as response:
                content = response.read()
                if b"<!DOCTYPE" in content.upper() or b"<!ENTITY" in content.upper():
                    raise ValueError("Unexpected XML declaration in API response")
                return ET.fromstring(content) if content else ET.Element("response")
        except urllib.error.HTTPError as exc:
            if method == "GET" and missing_ok and exc.code == 404:
                return None
            raise RuntimeError(f"Jamf Classic {method} {resource.split('/')[0]} returned HTTP {exc.code}") from None
        except urllib.error.URLError:
            raise RuntimeError("Jamf Classic connection failed; check TLS and network access") from None

