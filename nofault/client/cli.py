"""``nofault`` command-line client.

Thin glue over the library. Passphrases are read interactively (getpass) or, for
automation/testing, from the ``NOFAULT_PASSPHRASE`` environment variable. The
client home (keystore + repo index + shred-vault) defaults to ``$NOFAULT_HOME``
or ``~/.config/nofault``.

This CLI is intentionally minimal; the rich authoring UX (editor, preview,
browse, revision history) is the planned browser/desktop front-end. See
``docs/ARCHITECTURE.md``.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from ..bundle import Bundle
from ..crypto import shamir
from ..crypto.identity import (
    Identity,
    new_salt,
    read_keystore_seed,
    write_keystore,
)
from ..render.html import render_page
from .repo import Repo
from .safety import DeadManSwitch, panic
from .transport import RelayClient


def _home(args) -> str:
    home = args.home or os.environ.get("NOFAULT_HOME") or os.path.expanduser("~/.config/nofault")
    os.makedirs(home, exist_ok=True)
    return home


def _keystore_path(home: str) -> str:
    return os.path.join(home, "keystore.json")


def _passphrase(prompt: str = "Passphrase: ") -> str:
    env = os.environ.get("NOFAULT_PASSPHRASE")
    return env if env is not None else getpass.getpass(prompt)


def _identity(args) -> tuple[Identity, str]:
    home = _home(args)
    ks = _keystore_path(home)
    if not os.path.exists(ks):
        sys.exit("no identity found; run `nofault init` first")
    seed = read_keystore_seed(ks, _passphrase())
    return Identity.from_seed(seed), home


def _repo(args) -> Repo:
    identity, home = _identity(args)
    return Repo(os.path.join(home, "repo"), identity)


# --- commands ------------------------------------------------------------

def cmd_init(args) -> None:
    home = _home(args)
    ks = _keystore_path(home)
    if os.path.exists(ks) and not args.force:
        sys.exit("identity already exists (use --force to overwrite)")
    pw = _passphrase("New passphrase: ")
    salt = new_salt()
    from ..crypto.identity import derive_seed

    seed = derive_seed(pw, salt)
    duress_pw = None
    if args.with_duress:
        duress_pw = getpass.getpass("Duress (decoy) passphrase: ")
    write_keystore(ks, pw, seed, duress_passphrase=duress_pw)
    # persist the salt so the same passphrase reproduces the same identity on
    # re-init/recovery on another device
    with open(os.path.join(home, "salt"), "wb") as f:
        f.write(salt)
    ident = Identity.from_seed(seed)
    print(f"identity created: {ident.fingerprint}")
    print(f"publisher verify-key (enroll on relay): {ident.verify_key_bytes.hex()}")


def cmd_whoami(args) -> None:
    ident, _ = _identity(args)
    print(f"fingerprint: {ident.fingerprint}")
    print(f"publisher verify-key: {ident.verify_key_bytes.hex()}")
    print(f"box public-key: {ident.box_public_bytes.hex()}")


def _read_body(args) -> str:
    if args.body_file == "-":
        return sys.stdin.read()
    with open(args.body_file, encoding="utf-8") as f:
        return f.read()


def cmd_new(args) -> None:
    repo = _repo(args)
    encdoc = repo.create(args.title, _read_body(args), shreddable=args.shreddable)
    print(f"doc_id: {encdoc.manifest['doc_id']}")
    print(f"manifest_address: {encdoc.manifest_address}")


def cmd_edit(args) -> None:
    repo = _repo(args)
    encdoc = repo.edit(args.doc_id, title=args.title, body_markdown=_read_body(args))
    print(f"new version: {encdoc.manifest['version']}  {encdoc.manifest_address}")


def cmd_list(args) -> None:
    repo = _repo(args)
    for d in repo.list_docs():
        flag = " [shreddable]" if d["shreddable"] else ""
        print(f"{d['doc_id']}  v{d['version']}  {d['manifest_address']}{flag}")


def cmd_publish(args) -> None:
    repo = _repo(args)
    client = _relay_client(args)
    encdoc = repo.get_encrypted(args.doc_id)
    addr = client.publish(encdoc, repo.identity)
    print(f"published {args.doc_id} -> {addr}")


def cmd_fetch(args) -> None:
    client = _relay_client(args)
    encdoc = client.fetch(args.manifest)
    if args.out:
        from ..crypto.document import decrypt_document

        ident, _ = _identity(args)
        doc = decrypt_document(encdoc, ident)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(render_page(doc.title, doc.body_markdown))
        print(f"wrote {args.out}")
    else:
        print(f"fetched + verified: {encdoc.manifest_address}")


def cmd_open(args) -> None:
    repo = _repo(args)
    doc = repo.open(repo.get_encrypted(args.doc_id))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(render_page(doc.title, doc.body_markdown))
        print(f"wrote {args.out}")
    else:
        print(f"# {doc.title}\n\n{doc.body_markdown}")


def cmd_delete(args) -> None:
    repo = _repo(args)
    addrs = repo.delete(args.doc_id)
    if args.relay:
        client = _relay_client(args)
        # unpin best-effort (relay delete is operator-gated in production)
        for a in addrs:
            try:
                client._http.request("DELETE", f"/blob/{a}")
            except Exception:  # nosec B110 - unpin is best-effort; failures are non-fatal
                pass
    print(f"deleted {args.doc_id} (unpinned {len(addrs)} blobs locally)")


def cmd_shred(args) -> None:
    repo = _repo(args)
    print("shredded" if repo.crypto_shred(args.doc_id) else "not shreddable / unknown")


def cmd_panic(args) -> None:
    home = _home(args)
    try:
        repo = _repo(args)
    except SystemExit:
        repo = None
    result = panic(keystore_path=_keystore_path(home), repo=repo)
    print(f"panic: destroyed {', '.join(result['destroyed']) or 'nothing'}")


def cmd_verify(args) -> None:
    with open(args.in_path, "rb") as f:
        data = f.read()
    try:
        bundle = Bundle.from_tar_bytes(data)
    except ValueError as exc:
        sys.exit(f"INVALID bundle: {exc}")
    if args.author_fingerprint:
        from ..crypto.document import verify as verify_doc

        ok = all(
            verify_doc(d, expected_author_fingerprint=args.author_fingerprint)
            for d in bundle.docs
        )
        if not ok:
            sys.exit("INVALID: author fingerprint mismatch")
    print(f"VALID bundle: {len(bundle.docs)} document(s), author {bundle.author_verify_key.hex()[:16]}...")


def cmd_export(args) -> None:
    repo = _repo(args)
    bundle = _bundle_for(repo, args.doc_ids or [d["doc_id"] for d in repo.list_docs()])
    data = bundle.to_tar_bytes(repo.identity)
    with open(args.out, "wb") as f:
        f.write(data)
    print(f"wrote bundle {args.out} ({len(bundle.docs)} docs, {len(data)} bytes)")


def cmd_recovery_split(args) -> None:
    _, home = _identity(args)
    seed = read_keystore_seed(_keystore_path(home), _passphrase())
    shares = shamir.split(seed, args.threshold, args.shares)
    print(f"# {args.threshold}-of-{args.shares} recovery shares — distribute separately")
    for x, s in shares:
        print(f"{x}:{s.hex()}")


def cmd_recovery_combine(args) -> None:
    shares = []
    for token in args.shares:
        x, hexs = token.split(":", 1)
        shares.append((int(x), bytes.fromhex(hexs)))
    seed = shamir.combine(shares)
    home = _home(args)
    pw = _passphrase("New passphrase for recovered identity: ")
    write_keystore(_keystore_path(home), pw, seed)
    print(f"identity recovered: {Identity.from_seed(seed).fingerprint}")


def cmd_deadman(args) -> None:
    import time

    home = _home(args)
    dms = DeadManSwitch(os.path.join(home, "deadman.json"))
    if args.action == "arm":
        dms.arm(interval_seconds=args.interval, release_bundle_path=args.bundle, now=time.time())
        print("armed")
    elif args.action == "checkin":
        dms.check_in(now=time.time())
        print("checked in")
    elif args.action == "check":
        fired = dms.fire(now=time.time())
        print(f"FIRE: publish {fired}" if fired else "ok (not expired)")


# --- helpers -------------------------------------------------------------

def _relay_client(args) -> RelayClient:
    if getattr(args, "tor", False):
        return RelayClient.over_tor(args.relay, socks_port=args.socks_port)
    import httpx

    return RelayClient(httpx.Client(base_url=args.relay, timeout=60.0))


def _bundle_for(repo: Repo, doc_ids: list[str]) -> Bundle:
    docs = [repo.get_encrypted(doc_id) for doc_id in doc_ids]
    return Bundle(docs=docs, author_verify_key=repo.identity.verify_key_bytes)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nofault", description="Zero-knowledge publishing client")
    p.add_argument("--home", help="client home dir (default $NOFAULT_HOME or ~/.config/nofault)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init"); s.add_argument("--force", action="store_true")
    s.add_argument("--with-duress", action="store_true"); s.set_defaults(func=cmd_init)
    sub.add_parser("whoami").set_defaults(func=cmd_whoami)

    s = sub.add_parser("new"); s.add_argument("--title", required=True)
    s.add_argument("--body-file", required=True); s.add_argument("--shreddable", action="store_true")
    s.set_defaults(func=cmd_new)

    s = sub.add_parser("edit"); s.add_argument("--doc-id", required=True)
    s.add_argument("--title", required=True); s.add_argument("--body-file", required=True)
    s.set_defaults(func=cmd_edit)

    sub.add_parser("list").set_defaults(func=cmd_list)

    s = sub.add_parser("open"); s.add_argument("--doc-id", required=True)
    s.add_argument("--out"); s.set_defaults(func=cmd_open)

    s = sub.add_parser("publish"); s.add_argument("--doc-id", required=True)
    _relay_args(s); s.set_defaults(func=cmd_publish)

    s = sub.add_parser("fetch"); s.add_argument("--manifest", required=True)
    s.add_argument("--out"); _relay_args(s); s.set_defaults(func=cmd_fetch)

    s = sub.add_parser("delete"); s.add_argument("--doc-id", required=True)
    _relay_args(s, required=False); s.set_defaults(func=cmd_delete)

    s = sub.add_parser("shred"); s.add_argument("--doc-id", required=True); s.set_defaults(func=cmd_shred)
    sub.add_parser("panic").set_defaults(func=cmd_panic)

    s = sub.add_parser("export"); s.add_argument("--out", required=True)
    s.add_argument("doc_ids", nargs="*"); s.set_defaults(func=cmd_export)

    s = sub.add_parser("verify"); s.add_argument("--in", dest="in_path", required=True)
    s.add_argument("--author-fingerprint"); s.set_defaults(func=cmd_verify)

    s = sub.add_parser("recovery-split"); s.add_argument("--shares", type=int, required=True)
    s.add_argument("--threshold", type=int, required=True); s.set_defaults(func=cmd_recovery_split)

    s = sub.add_parser("recovery-combine"); s.add_argument("shares", nargs="+")
    s.set_defaults(func=cmd_recovery_combine)

    s = sub.add_parser("deadman"); s.add_argument("action", choices=["arm", "checkin", "check"])
    s.add_argument("--interval", type=int, default=86400); s.add_argument("--bundle", default="")
    s.set_defaults(func=cmd_deadman)
    return p


def _relay_args(s, required: bool = True) -> None:
    s.add_argument("--relay", required=required)
    s.add_argument("--tor", action="store_true")
    s.add_argument("--socks-port", type=int, default=9050)


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
