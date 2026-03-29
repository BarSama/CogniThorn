"""GitHub API wrapper for self-healing PR creation."""
import logging
from github import Github, GithubException
from shared.config.settings import settings

logger = logging.getLogger(__name__)


def get_repo():
    if not settings.github_token or not settings.github_repo:
        raise RuntimeError("GITHUB_TOKEN and GITHUB_REPO must be set for self-healing")
    g = Github(settings.github_token)
    return g.get_repo(settings.github_repo)


def get_default_branch(repo) -> str:
    return repo.default_branch


def create_branch(repo, branch_name: str, base_branch: str) -> None:
    base = repo.get_branch(base_branch)
    repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=base.commit.sha)
    logger.info("Created branch: %s", branch_name)


def commit_file(repo, branch: str, path: str, content: str, message: str) -> None:
    try:
        existing = repo.get_contents(path, ref=branch)
        repo.update_file(path, message, content, existing.sha, branch=branch)
    except GithubException:
        repo.create_file(path, message, content, branch=branch)
    logger.info("Committed %s to %s", path, branch)


def create_pull_request(repo, title: str, body: str, head: str, base: str) -> str:
    pr = repo.create_pull(title=title, body=body, head=head, base=base)
    logger.info("Created PR #%d: %s", pr.number, pr.html_url)
    return pr.html_url
