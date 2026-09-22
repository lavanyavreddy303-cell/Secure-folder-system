import os
import sys
import subprocess
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

def run_command(cmd, cwd=None, shell=False):
    try:
        result = subprocess.run(cmd, shell=shell, capture_output=True, text=True, cwd=cwd)
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)


def main():
    root = Path(__file__).parent.parent
    report_file = root / "ERROR_REPORT.md"
    
    problems = 0
    
    with open(report_file, "w", encoding="utf-8") as f:
        f.write("# Error Report\n\n")
        
        # 1. Pytest
        f.write("## Pytest\n")
        ok, stdout, stderr = run_command([sys.executable, "-m", "pytest", "-q"], cwd=root)
        if ok:
            f.write("✅ Pytest passed.\n\n")
        else:
            problems += 1
            f.write(f"❌ Pytest failed:\n```text\n{stdout}\n{stderr}\n```\n\n")
            
        # 2. Smoke Test
        f.write("## Smoke Test\n")
        ok, stdout, stderr = run_command([sys.executable, "scripts/smoke_test.py"], cwd=root)
        if ok:
            f.write("✅ Smoke test passed.\n\n")
        else:
            problems += 1
            f.write(f"❌ Smoke test failed:\n```text\n{stdout}\n{stderr}\n```\n\n")
            
        # 3. Static Checks (Python compile)
        f.write("## Static Checks\n")
        ok, stdout, stderr = run_command([sys.executable, "-W", "error", "-c", "import web.server, core.pipeline, core.keys"], cwd=root)
        if ok:
            f.write("✅ Import compilation passed.\n\n")
        else:
            problems += 1
            f.write(f"❌ Import compilation failed:\n```text\n{stderr}\n```\n\n")

            
        # 4. Grep Checks
        f.write("## Grep Checks (Security)\n")
        bad_patterns = [
            "backend=", "PKCS1v15", "ECB", "CBC", "debug=True", "0.0.0.0"
        ]
        grep_failures = []
        for pat in bad_patterns:
            ok, stdout, stderr = run_command(f'git grep "{pat}" -- "*.py"', cwd=root)
            if ok and stdout.strip():
                grep_failures.append(f"Found '{pat}':\n{stdout.strip()}")
                
        if not grep_failures:
            f.write("✅ No security bad patterns found.\n\n")
        else:
            problems += len(grep_failures)
            f.write("❌ Security bad patterns found:\n```text\n")
            f.write("\n".join(grep_failures))
            f.write("\n```\n\n")

    print(f"Error report generated at {report_file}")
    if problems == 0:
        print("NO ERRORS FOUND")
        sys.exit(0)
    else:
        print(f"{problems} PROBLEMS FOUND")
        sys.exit(1)

if __name__ == "__main__":
    main()
