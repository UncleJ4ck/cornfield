---
layout: post
title: "Odoo: installing server modules without being an administrator"
subtitle: "the install guard asks whether the environment is elevated, not whether the caller is an admin, so any sudo() call site hands it away"
date: 2026-10-13
tags: [privilege-escalation, odoo, broken-access-control, bug-bounty]
category: research
tldr: "button_immediate_install is guarded by @assert_log_admin_access, which tests env.is_admin(), which is self.su or self.user._is_admin(). sudo() satisfies it. Two default call sites reach it on an elevated recordset with no caller check in between: an accounting fiscal-position action reachable by any employee, and pos.config.write() reachable by any POS user. Both install modules on the server, which loads and executes Python, alters the schema and reloads the registry. Each attacker is denied the same call directly. Fixed in 3442814d5 and 2ea452d03."
---

## the guard that checks the wrong subject

Installing a module in Odoo is an administrator operation, and for good reasons: it imports and executes the module's Python, runs its `post_init_hook`, applies data files, alters the database schema, and reloads the registry for every worker. `ir.module.module` is restricted to `base.group_system` in the ACL, and `button_immediate_install` carries a decorator on top of that.

Here is the decorator, copied out of `odoo/addons/base/models/ir_module.py`, applied at line 476:

```python
def assert_log_admin_access(method: T, /) -> T:
    """Decorator checking that the calling user is an administrator, and logging the call.

    Raises an AccessDenied error if the user does not have administrator privileges, according
    to `user._is_admin()`.
    """
    @functools.wraps(method)
    def check_and_log(self, *args, **kwargs):
        user = self.env.user
        origin = request.httprequest.remote_addr if request else 'n/a'
        log_data = (method.__name__, self.sudo().mapped('display_name'), user.login, user.id, origin)
        if not self.env.is_admin():
            _logger.warning('DENY access to module.%s on %s to user %s ID #%s via %s', *log_data)
            raise AccessDenied()
        _logger.info('ALLOW access to module.%s on %s to user %s #%s via %s', *log_data)
        return method(self, *args, **kwargs)
    return check_and_log
```

Read the docstring against the code. The docstring says the check is "according to `user._is_admin()`". The code tests `self.env.is_admin()`, and `Environment.is_admin()` at `odoo/orm/environments.py:182-185` is:

```python
def is_admin(self) -> bool:
    """ Return whether the current user has group "Access Rights", or is in
        superuser mode. """
    return self.su or self.user._is_admin()
```

Those are not the same predicate. `user._is_admin()` is a fact about the person. `env.is_admin()` is that fact **or** `self.su`, which is a fact about the recordset. The documented intent is the strict one and the implementation is the loose one, so `records.sudo().button_immediate_install()` passes for any caller. Elevation bypasses the `base.group_system` ACL at the same time, so both guards fall to the same call.

`self.su` is true for any elevated recordset. So `records.sudo().button_immediate_install()` passes the admin check regardless of who is calling, and elevation bypasses the ACL as well. Both guards fall to the same `sudo()`.

The detail that makes this a defect rather than a design choice is sitting two lines above the check. `sudo()` preserves the caller's uid, and the decorator already reads `self.env.user` and logs `user.login` and `user.id`. The information needed to decide correctly is in scope and already being written to the log. It records exactly who you are, then asks whether the environment is elevated.

So the bug is not in the decorator's location. It is that the predicate asks about the environment when it means to ask about the person.

## finding the call sites

Once you know the guard is defeated by elevation, the question becomes mechanical: which code paths reach `button_immediate_install` on an elevated recordset, and can a non-administrator reach that code path?

Two of them ship in default modules.

### instance 1: any employee, through accounting

`addons/account/models/partner.py`, `AccountFiscalPosition.action_create_foreign_taxes`, a public method callable over `/web/dataset/call_kw`:

```python
template_code = self.env['account.chart.template']._guess_chart_template(self.country_id)
template = self.env['account.chart.template']._get_chart_template_mapping()[template_code]
if not template['installed']:
    localization_module = self.env['ir.module.module'].search([('name', '=', template['module'])])
    localization_module.sudo().button_immediate_install()
created_records = self.env["account.chart.template"]._instantiate_foreign_taxes(...)
```

`account.fiscal.position` grants `base.group_user` read, and read is all the method needs before it reaches the install.

The call does eventually fail, with an `AccessError` on `account.account` creation. That failure is after the module has installed and committed, so it does not undo anything. A method that errors out is not the same as a method that did nothing, and this is a good reminder to check what happened before the exception rather than treating a traceback as a dead end.

### instance 2: any POS user, through a plain write

`addons/point_of_sale/models/pos_config.py`, `write()` ended at `self.sudo()._check_modules_to_install()`, and that helper was:

```python
expected = [fname.replace('module_', '') for fname in self._fields if fname.startswith('module_') if any(pos_config[fname] for pos_config in self)]
if expected:
    modules = self.env['ir.module.module'].sudo().search([('name', 'in', expected)])
    modules = modules.filtered(lambda module: module.state not in STATES)
    if modules:
        modules.button_immediate_install()
```

`pos.config` grants `group_pos_user` write. The module set comes from the `module_*` boolean fields the attacker is writing, so here the attacker picks from the list: `module_pos_restaurant`, `module_pos_hr`, `module_pos_avatax`, `module_pos_discount`, `module_pos_appointment`, `module_pos_sms`.

This one needs no special method. It is an ordinary `write()` on a record the role is meant to edit.

## the run, with the denial first

Each instance carries its own negative control, which is the same attacker making the same call directly:

```
$ ./deploy.sh
waiting for odoo to answer...
initialising database 'poc' with account + point_of_sale (a few minutes)...
$ python3 poc/poc.py
CONTROLS
  [PASS] C1 both attackers are non-system (and emp is not an accounting manager)
         emp system=False mgr=False | pos system=False
  [PASS] C2a employee calling button_immediate_install DIRECTLY is DENIED -- Access Denied
  [PASS] E1 employee installed a localization module via action_create_foreign_taxes
         l10n_ae: uninstalled -> installed
  [PASS] C2b POS user calling button_immediate_install DIRECTLY is DENIED -- Access Denied
  [PASS] E2 POS user installed 'pos_hr' via a plain pos.config.write()
         uninstalled -> installed; write returned OK
```

The POS arm separately:

```
pos_hr BEFORE: uninstalled
-- NEG CONTROL: posuser (group_pos_user, NOT system) direct button_immediate_install
    DENIED: Access Denied
pos_hr AFTER: installed
ACL bypassed: ir.module.module = group_system 1,1,1,1 ; pos.config = group_pos_user 1,1,0,0
```

`C2a` and `C2b` are what turn this from "a user did a thing" into a bypass. Odoo refuses these exact accounts the exact operation when asked plainly, and grants it when the same operation arrives through an elevated recordset.

## what I did not claim

This is not arbitrary remote code execution, and the report said so in those words. The code that loads is official Odoo module code, not code the attacker wrote. I looked for a path to free module choice and did not find one reachable from a non-admin: instance 1 is limited to modules declaring a chart template, instance 2 to the `module_*` fields on `pos.config`. `payment.provider.button_immediate_install` does take a writable `module_id` and would allow free choice, but `payment.provider` is `group_system` only, so a non-administrator cannot reach it.

What does follow is real enough. A module install adds models, access rules, groups and HTTP routes including unauthenticated ones, so a non-administrator can enlarge the server's attack surface, change accounting or POS configuration on a production database, and force a registry reload for every worker at will.

I scored it `CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H`, 8.0, and noted an `S:C` reading of 9.6 without claiming it, since the impacted component is the registry and the whole database rather than the fiscal position or POS config the attacker touched.

## the fixes

Odoo fixed both call sites rather than the decorator, which is the conservative choice. Changing `is_admin()` or the decorator predicate would ripple through every `sudo()` call site in the codebase.

Instance 1, commit [`3442814d5`](https://github.com/odoo/odoo/commit/3442814d57cd9420d7dc6d022d15cd5d1b3def74), internal ticket `opw-6563524`, authored 2026-07-06 and committed 2026-09-14:

```python
     def action_create_foreign_taxes(self):
+        if not (self.env.is_admin() or self.env.user.has_group('account.group_account_manager')):
+            raise AccessError(_("Only Accounting managers can create foreign taxes."))
         self.ensure_one()
```

Instance 2, commit [`2ea452d03`](https://github.com/odoo/odoo/commit/2ea452d03aa0cbfe360c539fb3b29a7b89aa7297), internal ticket `opw-6563386`, authored 2026-08-17 and committed 2026-09-15. This one is structural rather than a single guard. It stops elevating the whole helper and elevates only the operations that need it:

```python
-        pos_configs.sudo()._check_modules_to_install()
-        pos_configs.sudo()._check_groups_implied()
+        pos_configs._check_modules_to_install()
+        pos_configs._check_groups_implied()
```

and adds a central check that the install path now calls:

```python
+    def _check_pos_manager_access(self):
+        if not (self.env.is_admin() or self.env.user.has_group('point_of_sale.group_pos_manager')):
+            raise AccessError(_("Only Point of Sale managers can modify a Point of Sale configuration."))
```

Both verified present at `0f577f1d3a9bf80991b043695bfde9510593e301` on branch `19.0`. `_check_modules_to_install` now calls `self._check_pos_manager_access()` immediately before `modules.button_immediate_install()`.

Note what the POS fix really does: `sudo()` moved from the whole helper down to the individual writes that need elevation, and the authorization decision moved up to a named method. That is the correct shape. Elevation should wrap the narrowest operation that needs it, never the function that also contains the decision.

## the part I got wrong in the report

My submitted text said `button_immediate_install` "performs no permission check of its own." That is false. It is decorated with `@assert_log_admin_access`, which does check, and the check is satisfied by elevation. I posted the correction to the thread myself rather than waiting to be caught on it.

The finding did not change and the mechanism reads better for it. "There is no check" and "the check asks the wrong question" are different claims, and only the second one is true here. Getting that distinction wrong in a report is how you lose a triager's confidence in the parts they cannot verify quickly.

## report status

`ODOO-JAEBFJLE`, filed 2026-09-08, Resolved at Low.

Odoo moved it High to Low on the ground that the attacker cannot select an arbitrary module and the actor is an internal user. I tried one escalation, chaining a sibling finding's free module selection to install `payment_demo` and publish a money-free payment provider to anonymous visitors, with a runtime PoC. It was rejected on two grounds: impact does not transfer between reports, and the actor was still inside Odoo's internal trust boundary. I had said in advance that I would drop it if they held, so I dropped it.

## references

- [`account` fix, `3442814d5`](https://github.com/odoo/odoo/commit/3442814d57cd9420d7dc6d022d15cd5d1b3def74)
- [`point_of_sale` fix, `2ea452d03`](https://github.com/odoo/odoo/commit/2ea452d03aa0cbfe360c539fb3b29a7b89aa7297)
- [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
- [CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)
