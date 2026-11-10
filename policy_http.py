"""HTTP inspection using the policy already attached to the connection."""
from aidefense import HttpInspectionClient
from aidefense.runtime.http_models import HttpInspectRequest


class PolicyHttpInspectionClient(HttpInspectionClient):
    def _inspect(
        self,
        http_req,
        http_res,
        http_meta,
        metadata=None,
        config=None,
        request_id=None,
        timeout=None,
        policy_id=None,
    ):
        if config is not None or policy_id is not None:
            return super()._inspect(
                http_req, http_res, http_meta, metadata, config,
                request_id=request_id, timeout=timeout, policy_id=policy_id,
            )

        # SDK2.3 adds every rule when config is omitted. The lab's connection
        # already has a policy; leave that server-side protection in charge.
        request = HttpInspectRequest(
            http_req=http_req,
            http_res=http_res,
            http_meta=http_meta,
            metadata=metadata,
        )
        payload = self._prepare_request_data(request)
        self._validate_inspection_request(payload)
        response = self._request_handler.request(
            method="POST",
            url=self.endpoint,
            auth=self.auth,
            headers={"Content-Type": "application/json"},
            json_data=payload,
            request_id=request_id,
            timeout=timeout,
        )
        return self._parse_inspect_response(response)
