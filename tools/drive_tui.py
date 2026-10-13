"""Drive the netmon screen inside a private tmux server and print what it shows.

Usage: drive_tui.py <workdir> <cols> <rows> <mode>
mode: file | live
"""
import subprocess
import sys
import time

workdir, cols, rows, mode = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
SOCK = "netmon-test"


def tmux(*args, check=True):
    return subprocess.run(["tmux", "-L", SOCK, *args], capture_output=True, text=True, check=check)


def shot(title):
    time.sleep(0.6)
    out = tmux("capture-pane", "-p", "-t", "nm").stdout
    print(f"\n########## {title} ({cols}x{rows}) ##########")
    print(out.rstrip("\n"))


def keys(*ks):
    for k in ks:
        tmux("send-keys", "-t", "nm", k)
        time.sleep(0.08)


tmux("kill-server", check=False)
if mode == "file":
    cmd = "./target/release/netmon -r tests/fixtures/loopback-mixed.pcapng; echo EXIT=$?; sleep 30"
else:
    cmd = "./target/release/netmon -i lo -f 'host 127.0.0.2'; echo EXIT=$?; sleep 30"
tmux("new-session", "-d", "-s", "nm", "-x", cols, "-y", rows, "-c", workdir, cmd)
time.sleep(1.5)

if mode == "file":
    shot("1. just opened a saved capture")
    keys("Home")
    keys(*["Down"] * 17)
    shot("2. moved down to packet 18")
    keys("Tab")
    keys("Down", "Down", "Right", "Down", "Down", "Down")
    shot("3. focus on layers, moved into the tree")
    keys("Escape", "/")
    keys("d", "n", "s", "Enter")
    shot("4. filter: dns")
    keys("c")
    keys("?")
    shot("5. help overlay")
    keys("Escape", "g")
    keys("t", "t", "l")
    shot("6. glossary filtered to ttl")
    keys("Escape", "q")
    time.sleep(0.8)
    shot("7. after pressing q (expect EXIT=0 and a normal shell line)")
else:
    shot("1. live on loopback, waiting for traffic")
    subprocess.run(["ping", "-c", "3", "-i", "0.3", "127.0.0.2"], capture_output=True)
    subprocess.run(["dig", "-b", "127.0.0.2", "@127.0.0.53", "example.net", "A", "+short"], capture_output=True)
    shot("2. live after 3 pings and a DNS lookup")
    keys("q")
    time.sleep(0.8)
    shot("3. after q (expect EXIT=0)")
    left = subprocess.run("pgrep -af dumpcap | grep -v pgrep | wc -l", shell=True, capture_output=True, text=True).stdout.strip()
    print(f"dumpcap processes left running: {left}")

tmux("kill-server", check=False)
