---
layout: post
title: "Odoo CRM: the portal guard that only guards portal users"
subtitle: "an internal user with zero CRM rights reads and rewrites any lead in the database, because _assert_portal_write_access() short-circuits for anyone who is not already a portal user"
date: 2026-10-01
tags: [broken-access-control, odoo, cross-company, sudo, bug-bounty]
category: research
tldr: "website_crm_partner_assign exposes five public methods that write crm.lead under sudo(). The sole guard is _assert_portal_write_access(), and its first condition is self.env.user._is_portal(). For a base.group_user caller that is false, the whole check short-circuits, and the sudo write goes through unchecked. One employee with no sales rights at all reads tracked old values, forces lead conversion, batch-moves 20 leads to Won, and gets subscribed to the chatter and attachments of a lead on another company. Reported on Odoo 19.0, closed as accepted risk on insider-trust grounds, no fix shipped."
---

## tldr

`website_crm_partner_assign` ships five public JSON-RPC methods that write `crm.lead` under `sudo()`. They are supposed to be portal methods, meaning a reseller editing their own assigned leads from the portal, and they share one authorization guard: `_assert_portal_write_access()`. The guard begins with `if self.env.user._is_portal() and not self.env.su and ...`. For an ordinary internal user that first clause is false, so the whole condition short-circuits, no check runs, and the `sudo()` write lands.

The attacker holds `base.group_user` only, no CRM group, no Sales group, no admin flag, and is given a company B lead ID. They move the financial forecast, flip the stage to Won, swap the contact identity, batch-move 20 leads at once, read the originals back through tracking values, get subscribed to the lead's chatter, receive the next administrator email with the attached file bytes, and complete the activity with attacker-authored feedback. Every effect is paired with a company-B control that stays unchanged, and the account's own direct `crm.lead.read()` is refused.

Reported through Intigriti on 2026-09-15 against Odoo 19.0 at commit `faccb11c3ebaa25706ff087a7b033e4eb6ac2893`. Odoo closed it as **accepted risk** on 2026-09-30, on the ground that internal users are bound by contract and the design intent is that an internal user should never fall below the rights of a portal user. No fix shipped. The code is unchanged on the current 19.0 tip at the time of writing. Posting this because the mechanics are worth understanding even where the vendor decides not to fix.

## the guard, in one function

`addons/website_crm_partner_assign/models/crm_lead.py:36-41`:

```python
def _assert_portal_write_access(self):
    if (
        self.env.user._is_portal() and not self.env.su and
        self != self.filtered_domain([
            ('partner_assigned_id', 'child_of', self.env.user.commercial_partner_id.id)
        ])
    ):
        raise AccessError(_('Only users with commercial partner which is a parent of the assigned partner can edit this lead.'))
```

Read as a boolean. The author's intent is clear: raise when the caller is a portal user, is not in a sudo context, and is trying to write a lead not assigned to their commercial partner. That is the right rule for a portal user.

The problem is the condition is a conjunction. If any clause is false, nothing raises. `self.env.user._is_portal()` is false for a `base.group_user`. For that caller the whole check short-circuits to false and the function returns normally with no exception.

What happens next is `sudo()`. `addons/website_crm_partner_assign/models/crm_lead.py:251-283`:

```python
def update_lead_portal(self, values):
    self._assert_portal_write_access()
    # ...
    self.env['mail.activity'].sudo().create({...})
    # access checked with '_assert_portal_write_access' at method beginning
    lead.sudo().write(lead_values)

def update_stage_from_portal(self, stage_id):
    self._assert_portal_write_access()
    self.sudo().write({'stage_id': stage_id})
    return True
```

The comment above `lead.sudo().write` is the key tell. The author relied on the guard as the whole authorization, and the `sudo()` means Odoo's own ACL and company record-rule layers are not consulted on the write. For a `base.group_user` caller the guard short-circuits and the `sudo()` lands the write anyway. Five methods carry this shape: `update_lead_portal`, `update_contact_details_from_portal`, `update_stage_from_portal`, `partner_interested`, `partner_desinterested`.

The JSON-RPC entry point does not help. `addons/web/controllers/dataset.py:28-32` dispatches the caller-selected model and public method; `odoo/service/model.py:45-71` rejects private methods only, and `call_kw()` at `:74-97` browses the supplied IDs and calls the public method without adding a model CRUD check. Each public method is responsible for its own authorization.

## pinning the attacker's role before any claim

The negative controls are what carry the finding, so they are first:

```text
attacker uid=7 groups=['Role / User']   # base.group_user only
attacker company = 1
target lead 7 company = 1

### CONTROL: the attacker reads the lead directly
  crm.lead.read(7) -> AccessError
```

Same session, same user. `read` on the target lead is refused with `AccessError`. That is the baseline the exploit has to beat.

```text
### EXPLOIT: the unguarded portal methods, single company throughout
  writes ACCEPTED: ['update_lead_portal', 'update_contact_details_from_portal']
   expected_revenue  recovered=True
   partner_name      recovered=True
   email_from        recovered=True
   phone             recovered=True
  admin re-read after attack: expected_revenue=1.0 email_from=attacker@evil.example
```

The attacker is refused the direct read, and still writes four fields the lead carries and gets the original values back. That gap is the finding.

## reading the originals: tracking values plus a forced subscription

Every field the unguarded methods write is mail-tracked. Odoo stores the old value next to the new value on each change, and the filter that is supposed to hide those records only checks whether the caller lacks a field group:

```python
# addons/mail/models/mail_tracking_value.py:45-50
def has_field_access(tracking):
    if not tracking.field_id:
        return env.is_system()
    model = env[tracking.field_id.model]
    model_field = model._fields.get(tracking.field_id.name)
    return model._has_field_access(model_field, 'read') if model_field else False
```

None of `expected_revenue`, `partner_name`, `email_from`, `phone` carries a `groups=` on its field definition, so the filter returns true. If the caller is a follower of the record, the tracking row is readable.

The subscription part is handed over by `update_lead_portal` itself. When it creates a self-assigned `mail.activity` under `sudo()`, `mail.activity.create()` groups the related record IDs by assignee and calls `message_subscribe()` at `addons/mail/models/mail_activity.py:273-302`. A direct subscription attempt by the attacker is refused by `mail_thread.py:4639-4661`, which checks read access on the thread. The `sudo()` activity creation goes around that.

So the chain is: write a tracked field through the unguarded portal method, in the same call be subscribed to the thread, read the thread back through the ordinary client route `POST /mail/thread/messages` at `result.data["mail.message"][n].trackingValues[m].oldValue`.

```text
mail.message id=121   OLD='Project Nightingale Holdings'        NEW='ZZZ'
                      OLD='ceo.secret@companyb-victim.example'  NEW='attacker@evil.example'
                      OLD='+32-476-SECRET-9911'                 NEW='+00-000'
mail.message id=120   OLD=987654.0                              NEW=1.0
```

None of those four originals was ever transmitted by the attacker. They cannot be an echo of attacker input.

## the attribution control: the only thing that proves it is the exploit

A `C:H` claim built from one attacker observation is a reading of noise. The attribution control is a bystander account with the identical role, identical company, identical request, run in the same session, with no exploitation step:

```text
########## CONTROL 2: bystander, identical role and company, never exploited ##########
  uid=N  0 tracked old values
   expected_revenue  recovered=False
   partner_name      recovered=False
   email_from        recovered=False
   phone             recovered=False

########## RESULT ##########
PASS: attacker recovered 4/4, bystander recovered 0. Attribution proved.
```

Four from the attacker, zero from the bystander. The only variable between the two arms is the exploitation step. The script exits non-zero unless that asymmetry holds, and the harness prints FAIL when the exploitation step is removed.

## the integrity side: forced conversion, batch to Won, mail delivery of attached files

Beyond read, the chain writes with no interaction from the victim.

Forced conversion: `partner_interested()` at `addons/website_crm_partner_assign/models/crm_lead.py:218-249` posts a comment and converts a lead to an opportunity under `sudo()`.

Forced unassignment and spam: `partner_desinterested()` at the same block clears `partner_assigned_id`, records the attacker's partner as declined, optionally applies the spam tag, and writes the result under `sudo()`.

Batch-to-Won on 20 explicit leads with a sentinel. The accepted run moves 20 named company-B lead IDs to Won at 100% in one call, and a distinct unnamed sentinel lead in the same company remains byte-for-byte unchanged. The sentinel is the point: it rules out an incidental mass write.

Mail delivery. After the forced subscription, the next administrator post to the target lead goes through standard follower delivery. The accepted run captured `CRM-confidential-forecast.txt` arriving in the attacker's SMTP sink with SHA-256 `c673afeab149e1d063d9b8b95216d00ad828fa05b4fef01e747ec615065cdf32`, while a direct `ir.attachment.read()` on the same attachment was refused with `AccessError`. The non-subscribed control lead's equivalent chatter and distinct attachment stayed unreadable and undelivered. Historical chatter on the target created before subscription stayed denied before and after the chain.

Activity completion. The forced activity is assigned to the attacker, so `addons/mail/models/mail_activity.py:482-486` lets them complete it; `:537-562` browses the related record under `sudo()` and posts the feedback with `author_id=self.env.user.partner_id.id`. Attacker-authored feedback lands on hidden company-B targets.

## single company, single company, single company

I originally wrote the report as a cross-company demonstration, because that was the most vivid framing. Odoo's first reply quoted the multi-company clause: multi-company isolation is a logical convenience, not an iron-clad barrier. That was a fair reading of what I had sent, and the wrong frame for the actual bug.

The code gates on three ACL rows for `crm.lead`:

```text
addons/crm/security/ir.model.access.csv:2                          sales_team.group_sale_manager    1,1,1,1
addons/crm/security/ir.model.access.csv:3                          sales_team.group_sale_salesman   1,1,1,0
addons/website_crm_partner_assign/security/ir.model.access.csv:7   base.group_portal                1,0,0,0
```

`base.group_user` is not among them. The attacker in this report holds `base.group_user` and nothing else, so `crm.lead` is refused by the model ACL itself. The multi-company record rules are never reached. The clause and this finding are describing two different barriers.

Re-running the chain with no second company anywhere, same single-company Odoo database, same company 1 the admin owns on every install:

```text
main company id = 1
attacker uid=7 groups=['Role / User']
attacker company = 1, target lead 7 company = 1

### CONTROL: the attacker reads the lead directly
  crm.lead.read(7) -> AccessError

### EXPLOIT: the unguarded portal methods, single company throughout
  writes ACCEPTED: ['update_lead_portal', 'update_contact_details_from_portal']
   expected_revenue  recovered=True
   partner_name      recovered=True
   email_from        recovered=True
   phone             recovered=True
```

Same refusal on the direct read, same two writes accepted, same four originals recovered. No second company in the arm. The accounts that hold exactly this role in a real customer deployment are HR, warehouse, accounting and support staff. Those three ACL rows are what keep them out of the sales pipeline, and this path goes around all three without touching a company boundary.

## scoring

Lead score: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` = 8.1 High. The write side is `I:H` because the chain forces conversion, unassignment, 20-lead batch stage change with sentinel, and attacker-authored activity feedback with no interaction from the victim.

Odoo acknowledged the technical description was correct and the single-company arm reproduces. The classification stayed at accepted risk on a design judgement:

> "In practice, this is an acceptable trade-off for companies because internal users are employees/contractors, their identities are well-known, and they are bound by an employment contract. In addition, from a design perspective, it would not be correct for an internal user to have fewer rights than a portal user (who meets the `_assert_portal_write_access` condition)."

The design argument deserves one note for the record, because it concerns the access model rather than the severity call. The portal role is read-only on this model (`csv:7 base.group_portal,1,0,0,0`) and is scoped by `ir_rule.xml:8-9` to `[('partner_assigned_id','child_of',user.commercial_partner_id.id)]`. What the unguarded methods hand the internal caller is a write, through the `sudo()` inside them, scoped to every lead in the database. So on both axes this path leaves the internal user above the portal user, not below. The closest expression of the stated intent would be letting an internal user reach leads assigned to them, which is exactly the scope the portal path already enforces, and the ownership test is already written.

CWE-863 Incorrect Authorization.

## report status

Reported through Intigriti on 2026-09-15 against Odoo 19.0, commit `faccb11c3ebaa25706ff087a7b033e4eb6ac2893`. Triage verified on 2026-09-18 and forwarded to Odoo. First company reply on 2026-09-23 cited the multi-company clause and closed as accepted risk. After the single-company arm was added, Odoo acknowledged on 2026-09-28 that the clause did not apply and re-classified on insider-trust grounds, keeping the status at accepted risk. Final company reply on 2026-09-30 confirmed the classification stands.

No commit, no CVE, no fix. The five public methods and the guard are unchanged on `odoo/odoo` branch `19.0` at the time of writing. If you run `website_crm_partner_assign` on an Odoo 19.0 instance, the behaviour above is what any ordinary employee can do today.

## references

- [`website_crm_partner_assign` on GitHub](https://github.com/odoo/odoo/tree/19.0/addons/website_crm_partner_assign)
- [`_assert_portal_write_access()` on GitHub](https://github.com/odoo/odoo/blob/19.0/addons/website_crm_partner_assign/models/crm_lead.py#L36-L41)
- [CWE-863: Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html)
