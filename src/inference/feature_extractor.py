import re
from urllib.parse import parse_qs

class FeatureExtractor:

    SQL_PATTERN = re.compile(r"(union|select|drop|insert|--|;)", re.IGNORECASE)
    SCRIPT_PATTERN = re.compile(r"<script>|javascript:", re.IGNORECASE)
    PATH_TRAVERSAL_PATTERN = re.compile(r"\.\./")

    def extract_from_raw(self, data: dict):
        path = data.get("path", "")
        query = data.get("query", "")
        body = data.get("body", "")
        headers = data.get("headers", {})

        full_text = f"{path} {query} {body}"

        return {
            "endpoint_length": len(path),

            "has_sql": int(bool(self.SQL_PATTERN.search(full_text))),

            "has_script": int(bool(self.SCRIPT_PATTERN.search(full_text))),

            "has_path_traversal": int(bool(self.PATH_TRAVERSAL_PATTERN.search(full_text))),

            "param_count": self.count_params(query, body),

            "has_query": int(bool(query))
        }

    def count_params(self, query, body):
        count = 0

        if query:
            count += len(parse_qs(query))

        if body:
            count += len(parse_qs(body))

        return count