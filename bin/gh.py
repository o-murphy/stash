# coding: utf-8
import argparse
import os


import keychain
import console

_stash = globals()["_stash"]

try:
    import github
except ImportError:
    print("Could not import 'github', installing it...")
    _stash("pip install pygithub")


class GitHubRepoNotFoundError(Exception):
    pass


def setup_gh():
    keychainservice = "stash.git.github.com"
    try:
        user = dict(keychain.get_services())[keychainservice]
        pw = keychain.get_password(keychainservice, user)
        g = github.Github(user, pw)
        u = g.get_user()
        return g, u
    except KeyError:
        print("Please set up your GitHub user/password in the keychain service.")
        raise


def gh_fork(args):
    """Forks a repo to your own GitHub account."""
    if console:
        console.show_activity()
    try:
        g, user = setup_gh()
        other_repo = g.get_repo(args.repo)
        if other_repo:
            mine = user.create_fork(other_repo)
            print("fork created: {}/{}".format(mine.owner.login, mine.name))
        else:
            pass
    finally:
        if console:
            console.hide_activity()


def gh_create(args):
    """Creates a new repository."""
    kwargs = {
        "description": args.description,
        "homepage": args.homepage,
        "private": args.private,
        "has_issues": args.has_issues,
        "has_wiki": args.has_wiki,
        "has_downloads": args.has_downloads,
        "auto_init": args.auto_init,
        "gitignore_template": args.gitignore_template,
    }
    kwargs = {k: v for k, v in kwargs.items() if v is not None}
    console.show_activity()
    try:
        g, user = setup_gh()
        r = user.create_repo(args.name, **kwargs)
        print("Created %s" % r.html_url)
    finally:
        console.hide_activity()


def parse_branch(userinput):
    if ":" in userinput:
        owner, branch = userinput.split(":")
    else:
        owner = userinput
        branch = "master"
    return owner, branch


def parent_owner(user, reponame):
    return user.get_repo(reponame).parent.owner.login


def gh_pull(args):
    """Creates a pull request."""
    if console:
        console.show_activity()
    try:
        g, user = setup_gh()
        reponame = args.reponame
        baseowner, basebranch = parse_branch(args.base)
        if not baseowner:
            baseowner = parent_owner(user, reponame)
        if not args.head:
            args.head = ":"
        headowner, headbranch = parse_branch(args.head)
        if not headowner:
            headowner = user.login

        baserepo = g.get_user(baseowner).get_repo(reponame)

        kwargs = {}
        if args.issue:
            kwargs["issue"] = baserepo.get_issue(args.issue)
        else:
            kwargs["title"] = args.title or input("Enter pull title:")
            kwargs["body"] = args.body or input("Enter pull body:")

        kwargs["base"] = basebranch
        kwargs["head"] = ":".join([headowner, headbranch])
        pullreq = baserepo.create_pull(**kwargs)

        print("Created pull %s" % pullreq.html_url)
        print("Commits:")
        print([(x.sha, x.commit.message) for x in pullreq.get_commits()])
        print("Changed Files:")
        print([x.filename for x in pullreq.get_files()])
    finally:
        if console:
            console.hide_activity()
    print("success")


def gh_list_keys(args):
    """Lists user keys."""
    g, u = setup_gh()
    for key in u.get_keys():
        print("{}:\n {}\n".format(key.title, key.key))


def gh_create_key(args):
    """Adds a key to GitHub."""
    title = args.title
    default_keyfile = os.path.expanduser("~/.ssh/id_rsa.pub")
    public_key_path = args.public_key_path
    if not public_key_path:
        if not os.path.exists(default_keyfile):
            print("Creating a ssh key in ~/.ssh/")
            _stash("ssh-keygen -t rsa -b 2048")
        public_key_path = default_keyfile

    # if private key, use pub key
    if not public_key_path.endswith(".pub"):
        public_key_path += ".pub"

    if not os.path.exists(public_key_path):
        raise Exception("Public Key file not found!")
    g, u = setup_gh()
    with open(public_key_path) as pubkey:
        u.create_key(title, pubkey.read())


if __name__ == "__main__":
    # Main parser setup
    parser = argparse.ArgumentParser(
        prog="gh",
        description="A command-line tool for GitHub operations.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument('--version', action='version', version='%(prog)s 0.1')

    # Add subparsers for each command
    subparsers = parser.add_subparsers(dest="command", required=True, help="supported commands")

    # gh fork <repo>
    fork_parser = subparsers.add_parser("fork", help="forks a user/repo")
    fork_parser.add_argument("repo", help="repo name of form user/repo")
    fork_parser.set_defaults(func=gh_fork)

    # gh create <repo>
    create_parser = subparsers.add_parser("create", help="creates a new repo")
    create_parser.add_argument("name", help="repo name")
    create_parser.add_argument("-s", "--description", help="Repo description")
    create_parser.add_argument("-H", "--homepage", help="Homepage url")
    create_parser.add_argument("-p", "--private", action="store_true", help="private repo")
    create_parser.add_argument("-i", "--has_issues", action="store_true", help="has issues")
    create_parser.add_argument("-w", "--has_wiki", action="store_true", help="has wiki")
    create_parser.add_argument("-d", "--has_downloads", action="store_true", help="has downloads")
    create_parser.add_argument("-a", "--auto_init", action="store_true", help="create readme and first commit")
    create_parser.add_argument("-g", "--gitignore_template", help="create gitignore using string")
    create_parser.set_defaults(func=gh_create)

    # gh pull <repo> <base> <head>
    pull_parser = subparsers.add_parser("pull", help="create a pull request")
    pull_parser.add_argument("reponame", help="repo name")
    pull_parser.add_argument("base", help="base owner:branch")
    pull_parser.add_argument("head", nargs="?", help="head owner:branch [default: :]")
    pull_parser.add_argument("--title", "-t", help="Title of pull request")
    pull_parser.add_argument("--body", "-b", help="Body of pull request")
    pull_parser.add_argument("--issue", "-i", help="Issue number")
    pull_parser.set_defaults(func=gh_pull)

    # gh list_keys
    list_keys_parser = subparsers.add_parser("list_keys", help="list user keys")
    list_keys_parser.set_defaults(func=gh_list_keys)

    # gh create_key <title> [<public_key_path>]
    create_key_parser = subparsers.add_parser("create_key", help="add a key to github")
    create_key_parser.add_argument("title", help="key title")
    create_key_parser.add_argument("public_key_path", nargs="?", help="path to public key file")
    create_key_parser.set_defaults(func=gh_create_key)

    # Parse args and call the function
    args = parser.parse_args()
    args.func(args)
