---
layout: post
title: "Odoo payments: one real payment, unlimited paid orders"
subtitle: "two provider modules verified a payment with the gateway and never checked it belonged to the transaction they were about to settle"
date: 2026-10-13
tags: [auth-bypass, odoo, payment, bug-bounty]
category: research
tldr: "Mercado Pago and DPO both resolve a transaction from an attacker-controlled URL value, then verify a different attacker-chosen payment id with the gateway, then apply that verified result to the transaction they resolved earlier. Nothing binds the two together, and provider_reference has no uniqueness constraint. So you pay once, for real, and replay that one payment id against as many unpaid transactions as you like. Against the real DPO sandbox API on a stock odoo:19.0, one genuinely paid token flipped five unpaid transactions to done. Both halves are fixed: Mercado Pago in 0133e46f8, DPO in 2a6970318."
---

## the shape of the bug, before any code

A payment provider integration has to answer one question honestly: *did this specific transaction get paid?*

The safe way is to ask the gateway about a payment and then confirm the gateway's answer refers to the order you are settling. Both of these modules did the first half and skipped the second. They take a transaction from one attacker-controlled parameter, take a payment id from another attacker-controlled parameter, ask the gateway "is this payment good?", get back a truthful yes, and then apply that yes to the transaction they picked up earlier.

The gateway never lied. The verification call is real and the answer is correct. The module just asked about a different payment than the one it settled.

That makes the exploit cheap in a way that matters. You do not need to forge anything, break a signature, or guess a secret. You need one genuine payment of your own, and then the payment id you were legitimately given.

## the money version

The interesting attack is not paying someone else's bill. It is this:

1. Place five orders of your own.
2. Pay for one. For real, with your own card, for the real amount.
3. Take the payment id the provider hands you and replay it against the other four.

The merchant ships five orders and banks one payment. There is no per-payment limit and no idempotency, so five is just where I stopped counting.

## DPO, the one I drove against the live sandbox

`addons/payment_dpo/controllers/main.py`, before the fix:

```python
@staticmethod
def _verify_and_process(data):
    tx_sudo = request.env['payment.transaction'].sudo()._search_by_reference('dpo', data)
    if not tx_sudo:
        return
    try:
        payload = (
            f'<?xml version="1.0" encoding="utf-8"?>'
            f'<API3G>'
            f'<CompanyToken>{tx_sudo.provider_id.dpo_company_token}</CompanyToken>'
            f'<Request>verifyToken</Request>'
            f'<TransactionToken>{data.get("TransID")}</TransactionToken>'
            f'</API3G>'
        )
        verified_data = tx_sudo._send_api_request('POST', '', data=payload)
```

Two attacker-controlled values from the same query string, used for two different jobs and never compared. `_search_by_reference('dpo', data)` resolves the transaction from `data['CompanyRef']`. The verification asks about `data['TransID']`. Pick a victim reference in the first and your own paid token in the second.

The reason this reaches all the way to a confirmed order is a third absence: `payment.transaction.provider_reference` carries no uniqueness constraint, so the same provider payment id can be stamped on unlimited rows without the database objecting.

## the run

Stock `odoo:19.0` from Docker Hub, no modification to Odoo or the container, against DPO's real sandbox API. The token below was genuinely paid, by me, once.

```
$ ./deploy.sh
$ python3 poc.py
====================================================================
  LIVE PoC: payment substitution -- Odoo payment_dpo (CWE-639)
  Real DPO sandbox + stock odoo:19.0, zero modification
====================================================================

[STEP A] Attacker mints one genuinely paid DPO sandbox token
  [A3] verifyToken (the same call Odoo's controller makes)...
  [PASS] Attacker holds a genuinely paid DPO token (verifyToken Result=000)
  [+] Attacker's paid TransID: B907E0F6-...-EE9C56E2FD7B

  DPO-VICTIM-001: state=draft  provider_reference=(none)  amount=10.0
  DPO-VICTIM-002: state=draft  provider_reference=(none)  amount=10.0
  DPO-VICTIM-003: state=draft  provider_reference=(none)  amount=10.0
  DPO-VICTIM-004: state=draft  provider_reference=(none)  amount=10.0
  DPO-VICTIM-005: state=draft  provider_reference=(none)  amount=10.0
  [PASS] All 5 victim transactions start in state 'draft'
```

That block is the baseline and it is load-bearing. Five transactions, all `draft`, none carrying a provider reference. If any of them were already settled the rest of the run would prove nothing.

Then one `GET /payment/dpo/return` per victim, each carrying the victim's `CompanyRef` and the attacker's `TransID`:

```
  DPO-VICTIM-001: state=done  provider_reference=B907E0F6-...-EE9C56E2FD7B
  DPO-VICTIM-002: state=done  provider_reference=B907E0F6-...-EE9C56E2FD7B
  DPO-VICTIM-003: state=done  provider_reference=B907E0F6-...-EE9C56E2FD7B
  DPO-VICTIM-004: state=done  provider_reference=B907E0F6-...-EE9C56E2FD7B
  DPO-VICTIM-005: state=done  provider_reference=B907E0F6-...-EE9C56E2FD7B

  [PASS] All 5 victim transactions flipped draft -> done
  [PASS] All 5 carry the attacker's TransID as provider_reference
  [PASS] One paid token settled 5 transactions (no idempotency / no uniqueness)
  VERDICT: VULNERABLE  (5/5 checks passed)
```

All five rows carry the same provider reference. That repeated value is the clearest statement of the bug: the database is recording, truthfully, that one payment settled five orders.

## Mercado Pago, same defect, different parameter

`addons/payment_mercado_pago/controllers/payment.py` had the identical structure on `POST /payment/mercado_pago/webhook/<reference>` and on the checkout return route. The transaction comes from the URL path, the payment id comes from the body, the verification is real, and the binding is missing.

## the fixes

Both shipped, and both are the same idea: compare what the gateway answered about against what you are settling.

Mercado Pago, commit [`0133e46f8`](https://github.com/odoo/odoo/commit/0133e46f89df7dce8c39d2bacd29579d57a83fad), internal ticket `opw-3097856`, authored 2026-05-01 and committed 2026-07-10:

```python
         except ValidationError:
             _logger.error("Unable to verify the payment data")
         else:
+            if tx_sudo.reference != verified_data["external_reference"]:
+                _logger.warning("Received payment data with incorrect reference")
+                raise Forbidden()
             tx_sudo._process('mercado_pago', verified_data)
```

Three lines. The verified payment carries an `external_reference`, which is the merchant's own order reference, and the fix refuses to proceed when it does not match the transaction that was resolved from the URL. The test fixture gained `'external_reference': cls.reference` in the same commit, which is the part that keeps it fixed.

DPO, commit [`2a6970318`](https://github.com/odoo/odoo/commit/2a697031849f9bf33116834b90bc664d93d9034a), internal ticket `opw-6559197`, authored 2026-09-07 and committed 2026-10-07:

```python
+        provider_ref = data.get('TransactionToken')
+        if tx_sudo.provider_reference and provider_ref != tx_sudo.provider_reference:
+            _logger.warning("Received payment data with mismatching token.")
+            return
```

DPO needed one extra step, because there was nothing to compare against yet. The old code only learned the provider reference during `_apply_updates`, which is after the damage. So the fix also binds it at token-creation time:

```python
-        return transaction_data.get('TransToken')
+        else:
+            # Save the provider reference now, as the `verifyToken` request doesn't return it later
+            self.provider_reference = transaction_data.get('TransToken')
+            return self.provider_reference
```

Now the transaction knows which provider token it belongs to before any callback arrives, and a callback carrying a different token is dropped.

Worth noting what neither fix does: `provider_reference` still has no uniqueness constraint. The binding check makes the replay unreachable through these two controllers, which is the right fix for the reported bug. A database-level constraint would be the belt to that pair of braces, and it would cover any future provider that makes the same mistake.

## severity, and the argument that carried it

I scored it `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`, 7.5 High.

The attacker model, stated plainly because a tier without one is unauditable: an anonymous internet user with no Odoo account and no session. The only precondition is that the merchant has enabled Mercado Pago or DPO as a payment provider, and that the attacker can place an order and pay for it once, which is ordinary customer behaviour rather than a privilege. They need to know the victim transaction references, and in the worst-case path those are their own orders, so they already have them.

The metric worth defending is `I:H`. CVSS calls Integrity Low a modification where "the attacker does not have control over the consequence, or the amount of modification is constrained." Neither applies. The attacker picks exactly which transactions settle, the result is deterministic, and one payment validates an unbounded number of them.

I also made a point of distinguishing it from my own earlier Xendit finding, which was scored `I:L`. In the [Xendit case](/odoo-xendit-payment-no-access-token/) the attacker triggers a charge with their own card, so the merchant still gets the money and the harm is bounded at "paid someone else's order". Here the attacker pays once and the merchant ships N. Being explicit about why the weaker neighbouring finding was weaker is, in my experience, worth more at triage than another paragraph of adjectives.

There is an `A:L` reading I did not lead with: mass-validated orders reserve stock and take products out of sale, which would give 8.1. I noted it and did not claim it.

## what I did not prove

The DPO half was driven end to end against the real sandbox API. The Mercado Pago half was not. I established it by reading the controller and matching it to the same structure, and the fix Odoo shipped confirms the reading, but I did not stand up a live Mercado Pago merchant account and replay a real MP payment id. The report said so rather than implying both halves had the same evidence behind them.

One avenue died on the way. I wanted to show this reaching www.odoo.com, which would have moved it from a product defect to a live-service finding. It does not: odoo.com deploys neither DPO nor Mercado Pago as a payment provider, so there is nothing to hit. The finding is a defect in the product that lands on any tenant enabling either provider, and I scoped the report to the Odoo 19.0 asset instead of pretending otherwise.

## report status

Two submissions, because the second extended the first.

`ODOO-YJLTPJR2`, the Mercado Pago webhook handler, filed 2026-05-03 and Resolved. `ODOO-6ZOEK2CQ`, the same root cause written up across both Mercado Pago and DPO with the live sandbox run, filed 2026-05-22 and Resolved on 2026-10-12, five days after the DPO commit landed on the public branch.

Filing them as one report for two modules was deliberate. It is one bug class and one fix shape, and splitting it would have invited a duplicate ruling on the second.

Verified at `0f577f1d3a9bf80991b043695bfde9510593e301` on branch `19.0`: both checks are present in the shipping code.

## the takeaway

Every payment integration in a large application solves the same problem, which means they are a row of near-identical implementations and you only need one to drop a line. That is the same reason my [Xendit finding](/odoo-xendit-payment-no-access-token/) existed: read the row, find the odd one out.

The specific question to carry into the next one is narrower than "is the webhook authenticated". It is: **the thing the gateway verified and the thing the code is about to settle, are they provably the same object?** A verification call that returns a truthful answer about the wrong object is worse than no verification, because it reads like diligence in review. Both of these modules called the gateway. Both got a correct answer. Neither checked what the answer was about.

## references

- [`payment_mercado_pago` fix, `0133e46f8`](https://github.com/odoo/odoo/commit/0133e46f89df7dce8c39d2bacd29579d57a83fad)
- [`payment_dpo` fix, `2a6970318`](https://github.com/odoo/odoo/commit/2a697031849f9bf33116834b90bc664d93d9034a)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- [The Xendit finding, for the severity contrast](/odoo-xendit-payment-no-access-token/)
