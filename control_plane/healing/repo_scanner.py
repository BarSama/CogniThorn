"""Search the GitHub repo for files likely containing the vulnerability."""
import logging
from github import GithubException
from control_plane.healing.github_client import get_repo

logger = logging.getLogger(__name__)

ATTACK_KEYWORDS = {
    "sqli": ["query", "execute", "cursor", "sql", "db."],
    "xss": ["render", "innerHTML", "template", "escape", "sanitize"],
    "path_traversal": ["open(", "readfile", "send_file", "path"],
    "rce": ["exec(", "system(", "subprocess", "eval(", "os.popen"],
}


def find_candidate_files(attack_type: str, affected_parameter: str | None) -> list[dict]:
    """Return top 3 candidate (path, content) tuples from the GitHub repo."""
    try:
        repo = get_repo()
        keywords = ATTACK_KEYWORDS.get(attack_type, [])
        if affected_parameter:
            keywords = [affected_parameter] + keywords

        results = []
        for kw in keywords[:3]:
            try:
                items = repo.search_code(f"{kw} repo:{repo.full_name}")
                for item in list(items)[:3]:
                    try:
                        content = item.decoded_content.decode("utf-8", errors="replace")
                        results.append({"path": item.path, "content": content})
                        if len(results) >= 3:
                            return results
                    except Exception:
                        continue
            except GithubException as e:
                logger.warning("Code search failed for '%s': %s", kw, e)
                continue

        return results
    except Exception as e:
        logger.error("repo_scanner failed: %s", e)
        return []
