#!/usr/bin/env python3
"""Module creates a behavioral fingerprint based on zsh history file"""
import argparse
import logging
from base64 import b64encode, b64decode
from collections import Counter
from pathlib import Path
from sys import argv
from typing import Union, Optional

from hashes.simhash import simhash

MODULE_NAME = __file__.rsplit("/", maxsplit=1)[-1]

# Define lists of basic unwanted prefixes and suffixes for command segments
# This part of configuration is stable and should not be modified by anyone
UNWANTED_PREFIXES = ("|", ">", "+", "$", '"', "'", "\\", "http", "/", "~", ".")
UNWANTED_SUFFIXES = ("csv", "txt", "yml", "yaml", "json", "py", "sql", "pub", "md")

# Define default values for processing (parameters are included in payload)
HASHBITS = 64
SHINGLE_SIZE = 3
MAX_COMMAND_COMPLEXITY = 3
MAX_COMMANDS = 100
INCLUDE_FLAGS = True
CASE_INSENSITIVE = True
KNOWN_TOKEN_SEEN_TIMES_THRESHOLD = 10

# Compile parameters into one configuration set
CONFIGURATION = {
    "hashbits": HASHBITS,
    "shingle_size": SHINGLE_SIZE,
    "max_complexity": MAX_COMMAND_COMPLEXITY,
    "max_commands": MAX_COMMANDS,
    "include_flags": int(INCLUDE_FLAGS),  # as integer
    "case_insensitive": int(CASE_INSENSITIVE),  # as integer
    "known_token_threshold": KNOWN_TOKEN_SEEN_TIMES_THRESHOLD,
}

# Freeze log level at 'INFO' for all performed actions transparency
logging.basicConfig(format="%(asctime)s - %(name)s - %(message)s", level=logging.INFO)
log = logging.getLogger(MODULE_NAME)


def read_history_file(file_path: Union[str, Path]) -> list[str]:
    """
    Read and process history file with commands
    :param file_path: path to the file with history (test only with zsh history)
    :return: list of commands from the history file
    """
    log.info("read local history file '%s'", file_path)

    with open(file_path, mode="rb") as history_file:
        byte_rows: list[bytes] = history_file.read().splitlines()

    log.info("read %d byte rows from history file '%s'", len(byte_rows), file_path)

    def process_byte_row(byte_row: bytes) -> Optional[str]:
        """
        Process history entity as byte row, decode it and perform basic validation
        :param byte_row: history record as bytes
        :return: command as string (if decoded successfully), None otherwise
        """
        try:
            row = byte_row.decode(encoding="utf-8")
        except UnicodeDecodeError:
            log.debug("can not decode history record '%s', skip", str(byte_row))
            return

        if not row:
            log.debug("history record is empty, skip")
            return

        if not row.startswith(": ") or ";" not in row:
            log.debug("history record '%s' is invalid or corrupted, skip", row)
            return

        try:
            _, command = row.split(sep=";", maxsplit=1)
        except ValueError:
            log.debug("can not split value from history record '%s', skip", row)
            return

        command = str(command)  # enforce type
        if command.startswith("./"):
            return

        return command

    log.info("process byte rows from history file")

    commands = []
    for byte_row in byte_rows:
        history_command = process_byte_row(byte_row)
        if not history_command:
            log.debug("history record is empty, skip")
            continue

        commands.append(history_command)

    log.info("collected %d valid history records", len(commands))

    return commands


class HistoryFingerprint:
    """Create a fingerprint from the list of commands"""

    def __init__(
        self,
        commands: list[str],
        *,
        hashbits: int = HASHBITS,
        shingle_size: int = SHINGLE_SIZE,
        max_complexity: int = MAX_COMMAND_COMPLEXITY,
        max_commands: int = MAX_COMMANDS,
        include_flags: Union[bool, int] = INCLUDE_FLAGS,
        case_insensitive: Union[bool, int] = CASE_INSENSITIVE,
        known_token_threshold: int = KNOWN_TOKEN_SEEN_TIMES_THRESHOLD,
    ):
        """
        Initialize history fingerprint creator
        :param commands: list of history commands
        :param hashbits: number of simhash bits
        :param shingle_size: size of a shingle (length)
        :param max_complexity: number of first N arguments from the command to take
        :param max_commands: number of top commands to process
        :param include_flags: include '-flag', '--flags' as a part of the fingerprint
        :param case_insensitive: convert all segments to lowercase
        :param known_token_threshold: token is known if seen at least N times
        """
        self.commands = commands

        # semi-private
        self._hashbits = hashbits
        self._shingle_size = shingle_size
        self._max_complexity = max_complexity
        self._max_commands = max_commands
        self._include_flags = bool(include_flags)
        self._case_insensitive = bool(case_insensitive)
        self._known_token_threshold = known_token_threshold

        # available as property
        self._hash_instance: Union[None, simhash] = None

    def _count_tokens_from_commands(self) -> dict[str, int]:
        """
        Count unique tokens from commands
        :return: counter of unique tokens
        """
        log.info("count unique tokens from commands")

        tokens = []
        for command in self.commands:
            command_tokens = command.split(" ")
            tokens.extend(command_tokens)

        log.info(
            "collected %d non-unique tokens (single words) from %d history commands",
            len(tokens),
            len(self.commands),
        )

        counter = Counter(tokens)

        log.info(
            "store %d non-unique tokens as %d unique tokens",
            len(tokens),
            len(counter),
        )

        log.info(
            "top-5 most common tokens: %s",
            ", ".join(
                f"'{pair[0]}' ({pair[1]} times)" for pair in counter.most_common(5)
            ),
        )

        return dict(counter)  # enforce dict type

    def _get_main_commands(self, tokens_count: dict[str, int]) -> list[str]:
        """
        Get baseline (main) commands that were executed
        :param tokens_count: count of tokens
        :return: list of baseline commands
        """
        log.info("get baseline commands that were executed")

        main_commands = []
        for command in self.commands:
            segments = command.split(" ")

            main_command_tokens = []
            for segment in segments[: self._max_complexity]:
                if not segment:
                    break

                if CASE_INSENSITIVE:  # convert to lower to ignore case
                    segment = segment.lower()

                # If below the threshold, command segment is private or not common
                seen_count = tokens_count.get(segment, self._known_token_threshold)
                if seen_count is not None and seen_count < self._known_token_threshold:
                    break

                if segment.startswith("-"):
                    if INCLUDE_FLAGS:
                        main_command_tokens.append(segment)
                    break

                if "=" in segment and len(segment.split("=", maxsplit=1)) > 1:
                    break

                if segment.startswith(UNWANTED_PREFIXES):
                    break

                # Include common typos and cli mistakes (missed whitespace, etc.)
                if segment.endswith(UNWANTED_PREFIXES):
                    break

                if segment.endswith(UNWANTED_SUFFIXES):
                    break

                main_command_tokens.append(segment)

            main_command = " ".join(main_command_tokens)
            if not main_command:
                continue

            main_commands.append(main_command)

        log.info(
            "collected %d non-unique main commands from %d history commands using %d "
            "unique tokens",
            len(main_commands),
            len(self.commands),
            len(tokens_count),
        )

        return main_commands

    def _tokenize_main_commands(self, main_commands: list[str]):
        """
        Create a list of tokens from main commands
        :param main_commands: list of main commands
        :return: list of tokens
        """
        log.info("tokenize baseline commands")

        counter = Counter(main_commands)

        log.info(
            "store %d non-unique main commands as %d unique main commands",
            len(main_commands),
            len(counter),
        )

        log.info(
            "top-5 most common main commands: %s",
            ", ".join(
                f"'{pair[0]}' ({pair[1]} times)" for pair in counter.most_common(5)
            ),
        )

        most_common_commands_count = counter.most_common(self._max_commands)
        most_common_commands = [pair[0] for pair in most_common_commands_count]

        log.info(
            "top-5 most common tokens: %s",
            ", ".join(f"'{cmd}'" for cmd in most_common_commands[:5]),
        )

        return most_common_commands

    def _build_shingles_from_tokens(
        self, tokens: list[str], size: Optional[int] = None
    ) -> list[str]:
        """
        Turn tokens ("words") into shingles
        :param size: shingle size
        :return: list of shingles
        """
        if not size:
            size = self._shingle_size

        log.info("build shingles with length %d", size)

        # We want to preserve the order of the commands (since commands are sorted
        # as descending top), in order to do so we use shingles.
        # "If the application requires such similarity measure that demands the order
        # of appearance then shingle can be a good choice as feature", see:
        # https://github.com/sumonbis/NearDuplicateDetection
        segments = []

        for word in tokens:
            cmd_segments = word.split(" ")
            for cmd_segment in cmd_segments:
                segments.append(cmd_segment)

        shingles = []
        for index in range(max(len(segments) - size + 1, 1)):
            shingle = " ".join(segments[index : index + size])
            shingles.append(shingle)

        log.info(
            "shingle examples: %s",
            ", ".join([f"'{shingle}'" for shingle in shingles[:5]]),
        )
        log.info("built %d shingles with size %d", len(shingles), size)

        return shingles

    def calculate(self) -> int:
        """
        Calculate hash (or fingerprint), save the hash instance for later
        :return: hash as integer
        """
        tokens_count = self._count_tokens_from_commands()
        main_commands = self._get_main_commands(tokens_count)
        tokens = self._tokenize_main_commands(main_commands)

        shingles = self._build_shingles_from_tokens(tokens)

        self._hash_instance = simhash(shingles, hashbits=self._hashbits)

        return self._hash_instance.hash

    def compare(self, other_instance: simhash) -> float:
        """
        Compare fingerprint with another hash instance
        :param other_instance: another hash instance
        :return: similarity percent
        """
        return self._hash_instance.similarity(other_instance) * 100.0  # as percent

    @property
    def hash_instance(self) -> Union[None, simhash]:
        """
        Return hash instance
        :return: hash instance as simhash if exists
        """
        return self._hash_instance


def decode_fp(b64_payload: str) -> tuple[int, str, dict]:
    """
    Decode base64 payload with parameters
    :param b64_payload: encoded payload
    :return: decoded payload
    """
    log.info("decode passed base64 payload with fp '%s'", b64_payload)

    decoded = b64decode(b64_payload).decode("utf-8")

    log.info("decoded raw payload: '%s'", decoded)

    contact, fingeprint_hex, *raw_config = decoded.split(":")
    log.info("decoded fingerprint as hex value: '%s'", fingeprint_hex)

    fingerprint = int(fingeprint_hex, 16)
    log.info("decoded fingerprint as int value: %d", fingerprint)

    log.info("decoded contact info: '%s'", contact)
    log.info("decoded raw parameter values: '%s'", raw_config)

    log.info(
        "decoding parameters order: "
        "hashbits, shingle_size, max_complexity, max_commands, include_flags, case_insensitive, "
        "known_token_threshold"
    )

    config = {
        "hashbits": int(raw_config[0]),
        "shingle_size": int(raw_config[1]),
        "max_complexity": int(raw_config[2]),
        "max_commands": int(raw_config[3]),
        "include_flags": bool(raw_config[4]),
        "case_insensitive": bool(raw_config[5]),
        "known_token_threshold": int(raw_config[6]),
    }

    log.info("decoded parameters: '%s'", str(config))
    log.info("decoding is completed")

    return fingerprint, contact, config


def encode_fp(fingerprint: int, contact: str, config: Optional[dict] = None) -> str:
    """
    Include parameters and fingerprint itself into the payload
    :param fingerprint: fingerprint as int number
    :param contact: name or contact information of the initiator
    :param config: additional name arguments
    :return: base64 string including parameters and fingerprint
    """
    log.info("encode fingerprint")

    if not config:
        config = CONFIGURATION.copy()

    parameters = (
        "{hashbits}:{shingle_size}:{max_complexity}:{max_commands}:{include_flags}:"
        "{case_insensitive}:{known_token_threshold}".format(**config)
    )

    log.info(
        "encoding parameters order: "
        "hashbits, shingle_size, max_complexity, max_commands, include_flags, "
        "case_insensitive, known_token_threshold"
    )

    log.info("parameters prepared for encoding: '%s'", parameters)

    fingerprint_hex = hex(fingerprint)
    log.info("fingerprint prepared for encoding as hex value: '%s'", fingerprint_hex)

    # Remove colon (":") char to avoid parameters separator confusion
    contact = contact.replace(":", "<colon>")
    log.info("contact info to attach: '%s'", contact)

    payload = f"{contact}:{fingerprint_hex}:{parameters}"
    log.info("raw payload: '%s'", payload)

    b64_payload = b64encode(payload.encode("utf-8")).decode("utf-8")

    return b64_payload


def get_similarity_level(similarity: float) -> str:
    """
    Convert percent of similarity into readable level
    :param similarity: similarity percent
    :return: readable level
    """
    if similarity == 100.0:
        return "identical"
    if similarity > 99.0:
        return "almost identical"
    if similarity > 95.0:
        return "very similar"
    if similarity > 85.0:
        return "similar"
    if similarity > 75.0:
        return "not very similar"
    if similarity > 50.0:
        return "not similar"
    if similarity > 35.0:
        return "different"
    if similarity > 20.0:
        return "very different"

    return "totally different"


if __name__ == "__main__":
    if len(argv) < 2:
        print(f"usage: python3 {MODULE_NAME} --help")
        exit(1)

    parser = argparse.ArgumentParser(
        prog="history-fp",
        usage=f"python3 {MODULE_NAME} --help",
        description=(
            "history-fp creates fingerprint based on your commands history. "
            "Tested only with zsh."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    subparsers = parser.add_subparsers(
        title="supported modes",
        description="history-fp provides multiple action targets",
        help="create your own fingerprint or compare your usage with others",
        dest="mode",
    )

    create_parser = subparsers.add_parser(
        "create",
        help="create a fingerprint based on your history file",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    create_required_group = create_parser.add_argument_group(
        "required", description="strictly required parameters"
    )

    create_required_group.add_argument(
        "-hs",
        "--history",
        action="store",
        type=str,
        required=True,
        help="path to the history file (example: '~/.zsh_history')",
    )

    create_required_group.add_argument(
        "-c",
        "--contact",
        action="store",
        type=str,
        required=True,
        help=(
            "contact information associated with the fingerprint "
            "(example: 'name@example.com')"
        ),
    )

    create_configuration_group = create_parser.add_argument_group(
        "configuration", description="additional configuration parameters"
    )

    create_configuration_group.add_argument(
        "--hashbits",
        action="store",
        type=int,
        default=HASHBITS,
        required=False,
        help="number of bits for simhash hash",
    )

    create_configuration_group.add_argument(
        "--shingle-size",
        action="store",
        type=int,
        default=SHINGLE_SIZE,
        required=False,
        help="shingle size (length)",
    )

    create_configuration_group.add_argument(
        "--max-complexity",
        action="store",
        type=int,
        default=MAX_COMMAND_COMPLEXITY,
        required=False,
        help="number of first N segments from the command to process",
    )

    create_configuration_group.add_argument(
        "--max-commands",
        action="store",
        type=int,
        default=MAX_COMMANDS,
        required=False,
        help="number of top N commands (by usage) from history file to process",
    )

    create_configuration_group.add_argument(
        "--token-threshold",
        action="store",
        type=int,
        default=KNOWN_TOKEN_SEEN_TIMES_THRESHOLD,
        required=False,
        help="token is considered as known if seen at least N times",
    )

    create_configuration_group.add_argument(
        "--include-flags",
        action=argparse.BooleanOptionalAction,
        default=INCLUDE_FLAGS,
        required=False,
        help="include flags such as '-flag', '--flag' as a part of the command",
    )

    create_configuration_group.add_argument(
        "--case-insensitive",
        action=argparse.BooleanOptionalAction,
        default=CASE_INSENSITIVE,
        required=False,
        help="process history commands in case insensitive mode",
    )

    compare_parser = subparsers.add_parser(
        "compare",
        help="compare your history with provided fingerprint",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    compare_required_group = compare_parser.add_argument_group(
        "required", description="strictly required parameters"
    )

    compare_required_group.add_argument(
        "-p",
        "--payload",
        action="append",
        type=str,
        required=True,
        help="base64 fingerprint with included contact information and configuration",
    )

    compare_required_group.add_argument(
        "-hs",
        "--history",
        action="store",
        type=str,
        required=True,
        help="path to the history file (example: '~/.zsh_history')",
    )

    args = parser.parse_args()

    if args.mode == "create":
        config = {
            "hashbits": args.hashbits,
            "shingle_size": args.shingle_size,
            "max_complexity": args.max_complexity,
            "max_commands": args.max_commands,
            "include_flags": int(args.include_flags),  # as integer
            "case_insensitive": int(args.case_insensitive),  # as integer
            "known_token_threshold": args.token_threshold,
        }

        CONFIGURATION = config  # overwrite

        history_commands = read_history_file(args.history)

        analyzer = HistoryFingerprint(history_commands, **config)
        fp = analyzer.calculate()

        encoded_fp = encode_fp(fp, args.contact, config=config)

        print("=" * 50)
        print(f"payload with fingerprint: {encoded_fp}")

        exit(0)

    if args.mode == "compare":
        history_commands = read_history_file(args.history)

        results = []

        for payload in args.payload:
            passed_fp, contact, config = decode_fp(payload)
            passed_hash = simhash(hash=passed_fp, hashbits=config["hashbits"])

            # Config depends on passed payload
            analyzer = HistoryFingerprint(history_commands, **config)
            fp = analyzer.calculate()

            similarity = analyzer.compare(passed_hash)
            similarity_level = get_similarity_level(similarity)

            results.append((contact, similarity, similarity_level))

        print("=" * 50)
        for contact, similarity, similarity_level in results:
            print(
                f"match with '{contact}': {similarity}% similarity ({similarity_level})"
            )

        exit(0)

    print("invalid parameters, exit")
    exit(1)
