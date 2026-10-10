"""The identity mapping draft: what it maps, what it leaves out, and that secrets stay out of its output."""
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import urllib.error

spec = importlib.util.spec_from_file_location(
    "draft_mapping", Path(__file__).resolve().parents[1] / "deploy" / "native" / "draft-identity-mapping.py")
draft_mapping = importlib.util.module_from_spec(spec)
spec.loader.exec_module(draft_mapping)

ACCOUNTS = {
    "si:scout": {"uuid": "K1E", "kind": "silicon", "id": "si:scout", "status": "active",
                 "custodian": {"uuid": "8HV", "id": "c:ada"}},
    "c:ada": {"uuid": "8HV", "kind": "carbon", "id": "c:ada", "status": "active"},
    "c:oddly": {"uuid": "Zz9", "kind": "silicon", "id": "si:oddly", "status": "active"},
    "si:twin-a": {"uuid": "Tw1", "kind": "silicon", "id": "si:twin-a", "status": "active"},
    "si:twin-b": {"uuid": "Tw1", "kind": "silicon", "id": "si:twin-b", "status": "active"},
}


def resolve(identifier):
    if identifier in ACCOUNTS:
        return 200, ACCOUNTS[identifier]
    return 404, {"error": {"code": "account_not_found", "message": "no such id"}}


class Draft(unittest.TestCase):
    def test_maps_matching_accounts_and_explains_the_rest(self):
        rows = [("si:scout", "silicon"), ("c:ada", "carbon"), ("si:gone", "silicon"), ("c:oddly", "carbon"),
                ("si:twin-a", "silicon"), ("si:twin-b", "silicon")]
        resolved, left_out = draft_mapping.draft(rows, resolve, sleep=lambda _: None)
        self.assertEqual([(e["iam_public_id"], e["accounts_uuid"]) for e in resolved],
                         [("si:scout", "K1E"), ("c:ada", "8HV")])
        self.assertEqual(resolved[0]["custodian"], {"uuid": "8HV", "id": "c:ada"})
        reasons = {e["iam_public_id"]: e["reason"] for e in left_out}
        self.assertEqual(reasons, {"si:gone": "account_not_found", "c:oddly": "kind_differs",
                                   "si:twin-a": "uuid_shared_with_another_id",
                                   "si:twin-b": "uuid_shared_with_another_id"})

    def test_writes_the_file_link_identities_reads(self):
        resolved, left_out = draft_mapping.draft([("si:scout", "silicon"), ("si:gone", "silicon")], resolve,
                                                 sleep=lambda _: None)
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "mapping.csv"
            report = Path(directory) / "mapping.csv.report.json"
            draft_mapping.write(out, report, resolved, left_out, "http://accounts.example")
            self.assertEqual(out.read_text(), "iam_public_id,accounts_uuid\nsi:scout,K1E\n")
            summary = json.loads(report.read_text())
            self.assertEqual((summary["stored_ids"], len(summary["left_out"])), (2, 1))

    def test_lookup_waits_out_rate_limits_and_refuses_bad_credentials(self):
        calls, slept = [], []

        def opener(request, timeout):
            calls.append(request.full_url)
            if len(calls) == 1:
                raise urllib.error.HTTPError(request.full_url, 429, "slow down", {"Retry-After": "2"},
                                             io.BytesIO(b'{"error":{"code":"rate_limited"}}'))
            return _Response(200, json.dumps(ACCOUNTS["si:scout"]).encode())

        status, body = draft_mapping.lookup("http://accounts.example/", "hook", "sa_app_secret", "SI:Scout",
                                            opener=opener, sleep=slept.append)
        self.assertEqual((status, body["uuid"]), (200, "K1E"))
        self.assertEqual(calls, ["http://accounts.example/v1/accounts/by-id/si:scout"] * 2)
        self.assertEqual(slept, [2.0])

        def refused(request, timeout):
            raise urllib.error.HTTPError(request.full_url, 401, "no", {}, io.BytesIO(b'{"error":"invalid_client"}'))

        with self.assertRaises(draft_mapping.DraftError) as raised:
            draft_mapping.lookup("http://accounts.example", "hook", "sa_app_secret", "c:ada", opener=refused)
        self.assertNotIn("sa_app_secret", str(raised.exception))


class _Response(io.BytesIO):
    def __init__(self, status, body):
        super().__init__(body)
        self.status = status


if __name__ == "__main__":
    unittest.main()
