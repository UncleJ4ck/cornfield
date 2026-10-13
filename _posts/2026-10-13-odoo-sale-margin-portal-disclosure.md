---
layout: post
title: "Odoo sale_margin: the line was protected, the order total was not"
subtitle: "a portal customer reads the vendor's profit on their own quotation, and subtracts it to get the supplier cost"
date: 2026-10-13
tags: [info-disclosure, odoo, portal, bug-bounty]
category: research
tldr: "sale.order.line.margin carried groups=\"base.group_user\". sale.order.margin, the order-level total of exactly the same numbers, carried nothing. A portal customer is denied the line field and granted the order field, reads the vendor's profit on their own quotation, and derives the supplier cost with one subtraction: cost = amount_untaxed - margin. Fixed in cd992ceeb by giving the order-level fields the groups= their line-level counterparts always had."
---

## the missing-sibling shape

Some bugs are interesting because the mechanism is clever. This one is interesting because there is no mechanism at all. Two fields compute the same quantity at two levels of the same document, and one of them was given a visibility group while the other was not.

That pattern is worth hunting on purpose. When a developer protects a field, they protect the one they were looking at. The aggregate, the report view, the related field three models away, and the mobile API serializer all compute the same secret and get added later by someone else. The guard does not travel.

Here the secret is the vendor's profit margin, which is to say the vendor's supplier cost, which is the one number a customer must never have while negotiating.

## the two field definitions

`addons/sale_margin/models/sale_order_line.py`, the protected one:

```python
margin = fields.Float(
    "Margin", compute='_compute_margin',
    min_display_digits='Product Price', store=True,
    groups="base.group_user", precompute=True)
margin_percent = fields.Float(
    "Margin (%)", compute='_compute_margin', store=True,
    groups="base.group_user", precompute=True)
```

`addons/sale_margin/models/sale_order.py`, before the fix:

```python
margin = fields.Monetary("Margin", compute='_compute_margin', store=True)
margin_percent = fields.Float("Margin (%)", compute='_compute_margin', store=True, aggregator="avg")
```

Same name, same compute method name, same stored-on-the-record treatment. No `groups=`.

`groups="base.group_user"` restricts a field to internal users. A portal customer is not a `base.group_user`, which is the whole point of the portal tier. So the line field is correctly invisible to them and the order field, which is just the sum of those lines, is not.

```python
@api.depends('order_line.margin', 'amount_untaxed')
def _compute_margin(self):
    ...
    order.margin = sum(order.order_line.mapped('margin'))
    order.margin_percent = order.amount_untaxed and order.margin/order.amount_untaxed
```

The order-level value is literally `sum()` of the values the portal user is denied.

## proving it, controls first

A disclosure finding needs three things established before the payload: that the attacker is really the low tier, that the secret really exists, and that the intended guard really works. Otherwise a positive result might just be a misconfigured lab.

```
$ ./deploy.sh
[*] init l8db with sale_margin (+sale, account deps)
[*] ready on http://localhost:8725 (db l8db)
$ python3 poc.py http://localhost:8725 l8db
seeded order 2 for portal partner 14; admin-visible margin=400.0 (0.4)

CONTROLS
  [PASS] C1 attacker is a portal user (not internal)
  [PASS] C3 admin sees a non-zero margin (a real secret exists) -- margin=400.0
  [PASS] C2 portal reading sale.order.LINE.margin is DENIED (the intended guard) -- AccessError on line.margin
```

`C2` is the one that makes this a finding rather than a configuration note. The same portal session, on the same order, is refused the line-level margin with an `AccessError`. Odoo has a clear opinion about whether this customer may see margin data, and it is no.

Then the order-level read, same session:

```
EXPLOIT (portal user, own order)
  [PASS] portal reads sale.order.margin (vendor cost/profit)
         {"id": 2, "margin": 400.0, "margin_percent": 0.4, "amount_untaxed": 1000.0}
  derived product cost = amount_untaxed - margin = 1000.0 - 400.0 = 600.0  (real cost 600.0)
```

The last line is the impact in one subtraction. `amount_untaxed` is the price the customer is quoted and already knows. Subtract the margin and you have what the vendor paid their supplier. The derived figure matches the seeded cost exactly, so this is not an estimate.

No privilege escalation is involved. The customer reads their own order, which they are entitled to do. They are simply handed a field on it that Odoo denies them one level down.

## what it is not

The attacker only reaches orders they are a party to. This is not a cross-customer read, and I did not claim one. The value is per-quotation, so the exposure scales with how many quotations a customer receives rather than with the size of the database.

I also chased an extension that failed and is worth recording. `product_margin` exposes margin figures on `product.product`, which would have widened this from one order to the whole catalogue. It is refuted at runtime: those computes read `standard_price`, which is itself guarded, so the protection is transitive and the portal user gets nothing. The ceiling for this finding is the orders the customer is on.

## the fix

Commit [`cd992ceeb`](https://github.com/odoo/odoo/commit/cd992ceebbaf343c03e1941d39cfe423d35ba6c6), internal ticket `opw-6564338`, authored 2026-08-12 and committed to the public branch 2026-09-11:

```python
-    margin = fields.Monetary("Margin", compute='_compute_margin', store=True)
-    margin_percent = fields.Float("Margin (%)", compute='_compute_margin', store=True, aggregator="avg")
+    margin = fields.Monetary("Margin", compute='_compute_margin', store=True, groups="base.group_user")
+    margin_percent = fields.Float(
+        "Margin (%)", compute='_compute_margin', store=True, aggregator="avg", groups="base.group_user")
```

The commit message is the clearest statement of the bug anyone wrote, including me:

> Order-level margin values did not follow the same visibility rules as their line-level counterparts.

Verified present at `0f577f1d3a9bf80991b043695bfde9510593e301` on branch `19.0`.

The fix is the minimum correct change, and it is the right one. There was never a second mechanism to unpick, only a guard that had not been copied to the aggregate.

## severity

Filed at `CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`, 6.5, with a stated floor of 4.3 at `C:L`. Odoo settled it at Medium.

I argued `C:H` on the ground that supplier cost is the vendor's commercially sensitive figure and the disclosure is exact rather than approximate, and I wrote the 4.3 floor into the report myself rather than waiting to be argued down to it. On a program that devalues disclosure findings, naming your own floor costs nothing and makes the rest of the report easier to believe.

## how to find the next one

Grep the tree for a field carrying `groups=` and then look for every other field that computes the same value without it. Aggregates, `related=` hops, report models and API serializers are where the guard gets dropped, because each is written by someone solving a different problem than the person who added the protection.

`ODOO-1KS11CGB`, filed 2026-09-06, Resolved at Medium.

The lesson I keep from this one is about where to look rather than what was found. A guard on a field is a statement that somebody decided this data is sensitive. That decision is the valuable artefact, because it tells you a secret exists and names it. Then you go find every other place the same number surfaces, and you are no longer guessing about impact, only about reachability.

## references

- [The fix, `cd992ceeb`](https://github.com/odoo/odoo/commit/cd992ceebbaf343c03e1941d39cfe423d35ba6c6)
- [`sale_margin` on GitHub](https://github.com/odoo/odoo/tree/19.0/addons/sale_margin)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
