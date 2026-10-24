"""
One-command demo: starts a whole fake ONDC network behind the debugger.

    python -m mocks.demo              # start everything, run example purchases
    python -m mocks.demo --no-scenarios

What runs (logs in ./logs):
    debugger   :8000   open http://localhost:8000
    buyer      :8001   mock-buyer.example
    seller A   :8002   mock-seller-a.example   (reached via debugger /bpp)
    gateway    :8003   mock-gateway.example    (reached via debugger /gateway)
    seller B   :8004   mock-seller-b.example   (reached via debugger /bpp2)
    registry   :8005   public keys for everyone, like ONDC's registry

The debugger gets every public key from the mock registry, signing its lookups
with the buyer app's key, exactly as you would point it at preprod with your
own app's keys. No key file is used.

Press Ctrl+C to stop everything.
"""

import argparse
import os
import socket
import subprocess
import sys
import time

from mocks.keys import PARTICIPANTS, identity

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS = os.path.join(ROOT, "logs")

BUYER = identity("mock-buyer.example")
REGISTRY_ENV = {  # how the debugger finds and asks the registry
    "ONDC_REGISTRY": "http://localhost:8005/v2.0/lookup",
    "ONDC_SUBSCRIBER_ID": BUYER[0], "ONDC_UNIQUE_KEY_ID": BUYER[1], "ONDC_PRIVATE_KEY": BUYER[2],
}

APPS = [  # (name, module, port, extra environment)
    ("registry", "mocks.mock_registry:app", 8005, {}),
    ("buyer", "mocks.mock_buyer:app", 8001, {}),
    ("seller-a", "mocks.mock_seller:app", 8002,
     {"BPP_ID": "mock-seller-a.example", "BPP_URI": "http://localhost:8000/bpp"}),
    ("seller-b", "mocks.mock_seller:app", 8004,
     {"BPP_ID": "mock-seller-b.example", "BPP_URI": "http://localhost:8000/bpp2"}),
    ("gateway", "mocks.mock_gateway:app", 8003,
     {"SELLERS": "http://localhost:8000/bpp,http://localhost:8000/bpp2",
      "ONDC_REGISTRY": "http://localhost:8005/v2.0/lookup"}),
    ("debugger", "debugger.proxy:app", 8000,
     {"ROUTES": "bap=http://localhost:8001,bpp=http://localhost:8002,"
                "bpp2=http://localhost:8004,gateway=http://localhost:8003",
      "STALL_AFTER_SECONDS": "20", **REGISTRY_ENV}),
]

SCENARIOS = [  # (description, run_flow arguments)
    ("healthy purchase, search via the gateway to both sellers", ["--via-gateway"]),
    ("several bugs at once", ["--via-gateway", "--faults",
                              "select:late,init:bad,confirm:missing,search:missing@mock-seller-b"]),
    ("seller's on_select changed after it was signed, and on_init breaks the spec",
     ["--via-debugger", "--faults", "select:badsig,init:badtype"]),
    ("buyer sends init before on_select arrives; seller signs on_confirm with its retired key",
     ["--via-debugger", "--early", "init", "--faults", "confirm:oldkey"]),
    ("shopper walks away after select", ["--via-gateway", "--stop-after", "select"]),
]


def port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.2)
        return s.connect_ex(("127.0.0.1", port)) == 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-scenarios", action="store_true")
    args = parser.parse_args()

    for subscriber, key_id, _, _ in PARTICIPANTS:
        identity(subscriber, key_id)  # creates keys on first run
    busy = [p for _, _, p, _ in APPS if port_open(p)]
    if busy:
        sys.exit(f"ports already in use: {busy}. Stop whatever is using them and try again.")

    os.makedirs(LOGS, exist_ok=True)
    procs = []
    try:
        for name, module, port, extra in APPS:
            env = {**os.environ, **extra}
            env.pop("ONDC_KEYS", None)  # keys come from the mock registry, not a file
            log = open(os.path.join(LOGS, f"{name}.log"), "w")
            procs.append(subprocess.Popen([sys.executable, "-m", "uvicorn", module, "--port", str(port)],
                                          cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT))
        deadline = time.time() + 30
        while not all(port_open(p) for _, _, p, _ in APPS):
            if time.time() > deadline:
                sys.exit(f"apps didn't start in time; see {LOGS}")
            time.sleep(0.3)
        print("Fake ONDC network is up. Debugger: http://localhost:8000\n")

        if not args.no_scenarios:
            for description, flow_args in SCENARIOS:
                print(f"== {description}")
                subprocess.run([sys.executable, "-m", "mocks.run_flow", *flow_args], cwd=ROOT)
                print()
            print("Done. Results appear on the page as callbacks arrive and ttls expire;")
            print("'stopped partway' shows after 20 seconds of inactivity.\n")

        print("Running. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nstopping...")
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            p.wait(timeout=10)


if __name__ == "__main__":
    main()
