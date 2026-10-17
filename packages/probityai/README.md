# probityai

The `probity` command: one entry point for the evidence tools in
[probityai/probity](https://github.com/probityai/probity).

```sh
probity --help
probity verify case.json --policy policy.json
```

`probity verify` runs [probity-verify](https://github.com/probityai/probity/tree/main/packages/probity-verify).
Each tool registers its own subcommand through the `probity.commands` entry-point group, so `probity --help`
lists exactly the subcommands that are installed. The registration contract is in
[docs/architecture/MONOREPO.md](https://github.com/probityai/probity/blob/main/docs/architecture/MONOREPO.md#the-probity-command).

Licence: Apache-2.0.
