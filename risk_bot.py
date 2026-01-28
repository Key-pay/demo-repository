import os
import sys
import requests
import re

def main():
    # 1. Configuration & Inputs
    github_token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")  # e.g., "owner/repo"
    # In a pull_request event, GITHUB_REF is refs/pull/ID/merge
    # But usually github.event.number is passed if we use an action input or env
    # Simplest: use the event payload path or env var if we set it in workflow.
    # Let's assume we pass PR_NUMBER as env var from workflow.
    pr_number = os.environ.get("PR_NUMBER")

    if not github_token or not repo or not pr_number:
        print("Error: Missing environment variables (GITHUB_TOKEN, GITHUB_REPOSITORY, PR_NUMBER).")
        sys.exit(1)

    print(f"Starting Risk Bot for {repo} PR #{pr_number}")
    
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    # 2. Fetch PR Files (The "Diff")
    # Using the files endpoint is often easier/better than raw diff for analysis
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/files"
    
    files_data = []
    page = 1
    while True:
        params = {"per_page": 100, "page": page}
        resp = requests.get(url, headers=headers, params=params)
        if resp.status_code != 200:
            print(f"Error fetching files: {resp.status_code} {resp.text}")
            sys.exit(1)
        
        batch = resp.json()
        if not batch:
            break
        files_data.extend(batch)
        page += 1

    # 3. Analyze Risks
    
    risk_score = 0
    warnings = []
    
    total_additions = sum(f.get('additions', 0) for f in files_data)
    total_deletions = sum(f.get('deletions', 0) for f in files_data)
    total_changes = total_additions + total_deletions
    
    src_modified = False
    tests_modified = False
    
    # Secret Patterns (Basic Regex)
    secret_patterns = {
        "AWS Key": re.compile(r"AKIA[0-9A-Z]{16}"),
        "Generic Private Key": re.compile(r"BEGIN RSA PRIVATE KEY"),
        "DB Connection String": re.compile(r"://.*:.*@"),
        "Env File": re.compile(r"^\s*[A-Z_]+=.+$", re.MULTILINE) # Rough check for .env style lines in added code
    }

    # Risky Functions
    # Python: eval, exec, os.system, subprocess.call (simplified)
    # PHP: eval, exec, system, shell_exec, passthru
    risky_keywords = {
        ".py": ["eval(", "exec(", "os.system"],
        ".php": ["eval(", "exec(", "system(", "shell_exec(", "passthru("]
    }

    for f in files_data:
        filename = f['filename']
        patch = f.get('patch', '') # This is the diff for the file
        
        # Check folders for Test Coverage logic
        if filename.startswith("src/") or filename.startswith("app/"):
            src_modified = True
        if filename.startswith("tests/") or "test" in filename.lower():
            tests_modified = True

        # Analyze Patch Content
        if patch:
            # We only care about added lines usually, marked with '+'
            # But context lines share space. Let's just scan the patch for simplicity and safety.
            # (Scanning removed lines for secrets is "good" but usually we care about *new* secrets)
            # Let's filter for added lines to reduce false positives on removals.
            added_lines = [line[1:] for line in patch.split('\n') if line.startswith('+')]
            content_to_scan = "\n".join(added_lines)

            # Secret Detection
            for label, regex in secret_patterns.items():
                if regex.search(content_to_scan):
                    warnings.append(f"**Security**: Potential {label} detected in `{filename}`.")
                    risk_score += 10 # High risk

            # Risky Code Patterns
            ext = os.path.splitext(filename)[1]
            if ext in risky_keywords:
                for keyword in risky_keywords[ext]:
                    if keyword in content_to_scan:
                        warnings.append(f"**Security**: Risky function `{keyword}` detected in `{filename}`.")
                        risk_score += 5

    # Complexity Check
    if total_changes > 300:
        warnings.append(f"**Complexity**: PR is too large ({total_changes} lines). Consider breaking it down.")
        risk_score += 3
        
    # Test Coverage Check
    if src_modified and not tests_modified:
        warnings.append("**Quality**: Source code modified (src/ or app/) but no tests updated.")
        risk_score += 2

    # 4. Reporting
    
    # formatting the comment
    if risk_score > 0:
        status_emoji = "⚠️" if risk_score < 10 else "🚨"
    else:
        status_emoji = "✅"
    
    body = f"""## {status_emoji} Auto-Pilot Risk Report

**Risk Score**: {risk_score}

"""

    if warnings:
        body += "### Detected Issues:\n"
        for w in warnings:
            body += f"- {w}\n"
    else:
        body += "No high-risk checks failed. Good job!\n"

    print("posting comment...")
    print(body)
    
    # Post comment to PR
    # comments_url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    # Using issues endpoint because PRs are issues.
    
    post_url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    resp = requests.post(post_url, headers=headers, json={"body": body})
    
    if resp.status_code not in [200, 201]:
        print(f"Failed to post comment: {resp.status_code} {resp.text}")
        sys.exit(1)
        
    print("Success.")

if __name__ == "__main__":
    main()
