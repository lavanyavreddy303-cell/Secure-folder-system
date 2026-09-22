import subprocess
import sys

result = subprocess.run(
    [sys.executable, "-m", "pytest", "-q", "tests"],
    capture_output=True,
    text=True,
    cwd=r"c:\Users\deeksha v\OneDrive\Desktop\cryptix",
)
print(result.stdout)
if result.stderr:
    print(result.stderr)
print(f"\nReturn code: {result.returncode}")
