import tempfile
import unittest
from pathlib import Path

from scamtrace.repair import fix_roles, portable_screenshots


class RepairTests(unittest.TestCase):
    def test_fix_roles_preserves_contract_candidates_not_as_wallets(self):
        contract = {
            "value": "0xdac17f958d2ee523a2206206994597c13d831ec7",
            "context": '"token_address":"0xdac17f958d2ee523a2206206994597c13d831ec7"',
        }
        payment = {
            "value": "0x1111111111111111111111111111111111111111",
            "context": '"deposit_address":"0x1111111111111111111111111111111111111111"',
        }
        record = {
            "classification": "SCAM",
            "address_candidates": [contract.copy(), payment.copy()],
            "observations": [],
        }

        fix_roles(record)

        self.assertEqual(len(record["address_candidates"]), 2)
        self.assertEqual(
            [address["role"] for address in record["address_candidates"]],
            ["possible_contract", "possible_payment"],
        )
        self.assertEqual(
            [address["role"] for address in record["crypto_addresses"]],
            ["possible_contract", "possible_payment"],
        )

    def test_portable_screenshots_copies_only_source_folder_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "source"
            output = root / "reviewed"
            image = source / "evidence" / "page.png"
            image.parent.mkdir(parents=True)
            image.write_bytes(b"image")
            record = {
                "address_candidates": [],
                "crypto_addresses": [],
                "observations": [{"screenshot": str(image)}],
            }

            missing = portable_screenshots(record, source, output)

            copied = output / "evidence" / "page.png"
            self.assertEqual(missing, [])
            self.assertTrue(copied.is_file())
            self.assertEqual(record["observations"][0]["screenshot"], str(copied))

    def test_portable_screenshots_drops_out_of_scope_path(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "source"
            outside = root / "outside.png"
            outside.write_bytes(b"image")
            record = {
                "address_candidates": [],
                "crypto_addresses": [],
                "observations": [{"screenshot": str(outside)}],
            }

            missing = portable_screenshots(
                record,
                source,
                root / "reviewed",
            )

            self.assertIsNone(record["observations"][0]["screenshot"])
            self.assertEqual(
                missing,
                ["Screenshot path was outside the original run folder"],
            )
