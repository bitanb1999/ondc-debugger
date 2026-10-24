"""
Validate messages against ONDC's official API specs.

ONDC publishes each spec version as an OpenAPI file (build.yaml) in its spec
repositories, with a JSON schema for every action and a set of official
example messages. Download them with:  python -m debugger.fetch_spec

A catch, measured on ONDC's retail specs: many of ONDC's own examples fail
ONDC's own schemas (e.g. version 1.2.5: 45 of 377 pass). The schemas lag
behind the examples and the live network, so strict validation would flag
nearly every real message.

So each spec is "calibrated" when it loads: all of its official examples are
validated, and every schema rule they break is recorded as a known spec gap.
Those rules are skipped when checking your messages. Anything else your
message breaks is reported. ONDC's own examples can never cause an alarm,
while genuine mistakes (a missing field, a wrong type where the examples are
right) still show up.
"""

import glob
import os
from dataclasses import dataclass, field

import yaml
from jsonschema import Draft7Validator

try:  # the C-accelerated YAML loader is ~10x faster on these multi-MB files
    from yaml import CSafeLoader as _Loader
except ImportError:
    from yaml import SafeLoader as _Loader

SPEC_DIR = os.environ.get("ONDC_SPEC_DIR", "specs")
MAX_ERRORS = 8  # per message; the first few are what you need to fix


def _walk_examples(node):
    """Yield (action, message) for everything in the spec that looks like an ONDC message."""
    if isinstance(node, dict):
        ctx = node.get("context")
        if isinstance(ctx, dict) and "message" in node:
            yield ctx.get("action"), node
            return
        for value in node.values():
            yield from _walk_examples(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk_examples(value)


def _signature(action: str, error) -> tuple:
    """Which schema rule an error came from, independent of the message's data."""
    return (action, tuple(str(p) for p in error.absolute_schema_path))


def _where(error) -> str:
    return "/".join(str(p) for p in error.absolute_path) or "(top level)"


@dataclass
class Spec:
    name: str
    version: str
    doc: dict
    validators: dict = field(default_factory=dict)
    known_gaps: set = field(default_factory=set)
    examples_checked: int = 0

    def validator(self, action: str) -> Draft7Validator | None:
        if f"/{action}" not in self.doc.get("paths", {}):
            return None
        if action not in self.validators:
            # Use the whole spec as the schema, pointing at this action's request
            # body, so its internal "#/components/schemas/..." references resolve.
            root = dict(self.doc)
            root["$ref"] = f"#/paths/~1{action}/post/requestBody/content/application~1json/schema"
            self.validators[action] = Draft7Validator(root)
        return self.validators[action]

    def calibrate(self) -> None:
        for action, example in _walk_examples(self.doc.get("x-examples")):
            v = self.validator(action) if action else None
            if v is None:
                continue
            self.examples_checked += 1
            for error in v.iter_errors(example):
                self.known_gaps.add(_signature(action, error))

    def check(self, action: str, message: dict) -> tuple[list[str], int] | None:
        """Returns (problems, number of known-spec-gap errors skipped), or None if
        this spec doesn't define the action."""
        v = self.validator(action)
        if v is None:
            return None
        problems, skipped = [], 0
        for error in v.iter_errors(message):
            if _signature(action, error) in self.known_gaps:
                skipped += 1
            else:
                problems.append(f"{_where(error)}: {error.message[:160]}")
        return problems[:MAX_ERRORS] + (
            [f"...and {len(problems) - MAX_ERRORS} more"] if len(problems) > MAX_ERRORS else []), skipped


_specs: dict[str, Spec] | None = None


def load_specs() -> dict[str, Spec]:
    """All specs in SPEC_DIR, keyed by version (e.g. '1.2.0'). Loaded and calibrated once."""
    global _specs
    if _specs is None:
        _specs = {}
        for path in sorted(glob.glob(os.path.join(SPEC_DIR, "*.yaml"))):
            with open(path) as f:
                doc = yaml.load(f, Loader=_Loader)
            spec = Spec(name=os.path.basename(path), version=str(doc.get("info", {}).get("version")), doc=doc)
            spec.calibrate()
            _specs[spec.version] = spec
            print(f"[spec] loaded {spec.name} (version {spec.version}): calibrated on "
                  f"{spec.examples_checked} official examples, {len(spec.known_gaps)} known spec gaps skipped")
    return _specs


def spec_for(core_version: str | None) -> Spec | None:
    return load_specs().get(str(core_version)) if core_version else None
