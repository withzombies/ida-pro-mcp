# idap CLI Cheatsheet

## Bootstrap

```sh
idap daemon status || idap daemon start
eval "$(idap context ensure --shell)"
eval "$(idap context ensure --shell --force-new)"
```

## Sessions

```sh
idap sessions open <binary> --alias sample
idap sessions open /bin/ls --database-path /tmp/ls.i64 --alias ls
idap sessions list --json
idap sessions info sample
idap sessions use sample
idap sessions save /tmp/sample.i64 --session-ref sample
```

## Functions

```sh
idap funcs show main
idap funcs list --name-regex 'main|check_pw' --has-type
idap funcs list --calls recv --calls send --call-match any
idap funcs decompile main --summary
idap funcs disasm main --summary
idap funcs callers check_pw
idap funcs callees main
idap funcs strings main
idap funcs constants main
idap funcs basic-blocks main --limit 20
idap funcs callgraph main --direction both --max-depth 2
idap funcs export main --export-format prototypes
idap funcs stats
```

## Data and metadata

```sh
idap idb metadata
idap imports list --limit 20
idap imports list --module '*' --regex '.*'
idap globals list --regex 'flag|key'
idap strings list --regex 'password|token'
idap xrefs main --direction both --type any
idap xrefs field my_struct my_field
idap search regex 'password|token'
idap search bytes '7F 45 4C 46'
idap search refs code_ref main
```

## Types and stack

```sh
idap types list --kind struct --filter upnp --include-members --max-members 16
idap types structs search http
idap types structs read 0x401000 my_struct
idap types declare --decl 'typedef struct my_s { int a; } my_s;'
idap types set 0x401000 'int __fastcall main(int argc, const char **argv, const char **envp)'
idap types infer 0x401000 --depth 1
idap stack frame main
idap stack declare --from-json /tmp/stack-vars.json
idap stack delete --from-json /tmp/stack-delete.json
```

## Memory and conversion

```sh
idap memory bytes 0x401000 --size 32
idap memory int 0x401000 --width 8
idap memory string 0x402000 --max-len 80
idap memory global g_flag
idap memory table 0x404000 --width 8 --count 16 --resolve-names
idap convert int 0x41424344 --from auto
idap convert int 41424344 --from hex
idap convert int ABCD --from ascii
```

## Mutations and patches

```sh
idap rename 0x123e crackme_main
idap comment set 0x123e stage2-comment
idap comment append 0x123e finding-note
idap types enums upsert --name WCAppMsgInnerType --member WC_APPMSG_INNER_BRAND_MP_VIDEO=54
idap patch bytes 0x401000 '90 90'
idap patch asm 0x401000 'nop; nop'
idap py eval 'import idc; print(idc.get_cmt(0x123e, 0))'
```

## Escape hatches

```sh
idap raw list
idap raw schema set_type
idap raw call set_type '{"kind":"func","addr":"0x401000","type":"int __fastcall f(void)"}'
```

## Output shaping

Prefer:
- `--json`
- `--limit`
- `--offset`
- `--query`
- `--select`
- `--sort`
- `--summary`
- `--around`
- `--contains`
- `--lines`

Prefer first-class commands over:
- `idap raw call ...`
- `idap py eval ...`
