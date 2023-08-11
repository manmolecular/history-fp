"""Test fingerprint"""
import unittest

from fp import HistoryFingerprint, encode_fp, decode_fp
from hashes.simhash import simhash


class TestHistoryFingerprintSmoke(unittest.TestCase):
    def test_simhash_smoke(self) -> None:
        """
        Test that values matching some reference values,
        for example: https://asecuritysite.com/encryption/simhash
        :return: None
        """
        first = simhash("this is the first string", hashbits=256)
        second = simhash("this is the second string", hashbits=256)
        similarity = first.similarity(second)

        assert round(similarity, 5) == 0.92578

    def test_encode_decode(self) -> None:
        """
        Test that encoded and decoded results are the same (100% similarity)
        :return: None
        """
        history_commands = ["cd", "ls", "cat", "echo", "docker", "vim", "nano"]
        history_commands += [f"rand_{idx}" for idx in range(100)]  # trash filler

        # Encode local fingerprint
        analyzer = HistoryFingerprint(history_commands, known_token_threshold=0)
        local_fp = analyzer.calculate()
        local_encoded_fp = encode_fp(local_fp, "test")

        # Decode passed fingerprint and compare
        passed_fp, contact, config = decode_fp(local_encoded_fp)

        assert contact == "test"

        passed_hash = simhash(hash=passed_fp, hashbits=config["hashbits"])
        similarity = analyzer.compare(passed_hash)

        assert similarity == 100.0


if __name__ == "__main__":
    unittest.main()
