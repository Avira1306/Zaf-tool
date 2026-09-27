---
title: "How to Automate Financial Due Diligence in Excel with AI"
description: "What can be automated in an FDD engagement, what cannot, and how to do it inside Excel from trial balance import to commentary with the reviewer in charge."
date: 2026-04-29
updated: 2026-09-02
category: FDD workflow
image: /img/dashboard.webp
imageAlt: ZAF financial dashboard generated from a trial balance
---

The pitch for "AI due diligence" usually goes: upload the data room, receive a report. That sounds good until you are the person signing the report. This guide is about a narrower and more useful question: which parts of an FDD engagement are mechanical enough to automate, and how to automate them inside Excel so the judgement stays with the team.

## What an FDD engagement is actually made of

Strip an engagement down and it has six stages:

1. **Import.** Trial balances, general ledgers, management accounts, statutory accounts, often as PDFs, sometimes in another language.
2. **Map.** Each account to a reporting hierarchy: P&L lines, balance sheet lines, working capital and net debt classifications.
3. **Build.** The databook: P&L, balance sheet, NWC, net debt, cash flow, monthly and annual, with KPIs.
4. **Analyse.** Quality of Earnings, EBITDA bridge, working capital seasonality, net debt and debt-like items, revenue and customer concentration.
5. **Question.** Management questions arising from the gaps between the documents and the numbers.
6. **Report.** Commentary and schedules, in the firm's house style, in Word.

Stages one to three are almost entirely mechanical. Stage four is half mechanical (finding candidates) and half judgement (deciding). Stage five is generative work from a defined input. Stage six is drafting from structured data. That split tells you what to automate.

## Import: extraction is a solved problem

Financial statements in PDFs, scanned management accounts, images of a P&L in a CIM: extracting the tables into Excel is now reliable for typed documents and acceptable for scans with a review pass. The check that matters is the same as it always was: do the extracted totals agree with the totals on the page. An import index that lists every file, every table and its reconciliation status turns this from a hope into a control.

Translation is the other import task worth automating. A Nordic or DACH trial balance with 800 account descriptions in the local language used to cost a day; a model translates it in a minute and the mapping step becomes possible for anyone on the team.

## Map: AI suggests, the analyst confirms

Mapping is where most databook errors originate. Automating it means asking a model to suggest a hierarchy code for each account based on its description, number and balance behaviour, then presenting exceptions for review. The important design decisions:

- Suggestions are written to a mapping column, not applied silently. The analyst can filter to low-confidence rows.
- Unmapped accounts are flagged on a check sheet and the mapped total is compared to the TB total in every period.
- The mapping is saved as a template per client, so a later trial balance maps in seconds.

Done this way, mapping a new TB takes twenty minutes, and the twenty minutes are spent on the ten accounts that were ambiguous rather than the 790 that were obvious.

## Build: the databook is a function of the mapping

Once the TB is mapped, every schedule is deterministic: SUMIFS by hierarchy code by period. There is no reason for a human to build it, and several reasons not to (monthly and annual views drift; a late TB means a rebuild). The databook build should be a single action that produces every schedule as formulas linked to the mapped TB, with a source check on each sheet.

House style belongs here too. Fonts, number formats, header fills and bracket conventions are captured once and applied to every generated schedule, so the output does not need a formatting pass.

## Analyse: automate the finding, keep the deciding

This is where cloud platforms overreach and where a careful Excel implementation earns its keep.

Finding adjustment candidates is pattern recognition over ledger detail: spikes relative to run-rate, sign flips, round-number postings, accounts active in one period only, related-party names. A model is good at this and tireless. Deciding whether a candidate is an adjustment requires context the model does not have: what management said on the call, what the SPA will treat as debt-like, what the buyer's advisor will accept.

So the automation should produce a ranked list with reasons and cell references, and the schedule should accept or reject each item explicitly. Only accepted items flow to adjusted EBITDA. The audit trail is the list itself.

The EBITDA bridge, NWC seasonality and KPI calculations are mechanical once the mapping exists and should be one-click outputs with a tie-out to the P&L or balance sheet.

## Question: generate from the gaps

Management questions are a function of two inputs: what the documents claim and what the numbers show. A model given both can draft questions that cite the specific figure that prompted them ("Revenue in Q4 FY23 was 34% above the prior three-quarter average; what drove this?"). The team edits, adds the questions only experience produces, and tracks answers in a log. The generated draft saves the blank-page hour, not the thinking.

## Report: commentary from the schedule, beside the schedule

Commentary drafted by a model is only useful if every number in it can be traced to a cell. The design rule is that commentary is generated from a selected schedule and written next to it, quoting the sheet's figures, so the reviewer can check each sentence against the column it describes. Management's explanations are added as inputs, not invented. Export to Word takes the schedule and its commentary together, so the report and the databook never diverge.

## What this looks like in practice

A mid-market buy-side FDD on a single-entity target with a clean TB:

| Stage | Manual | Automated in Excel |
|---|---|---|
| Import and translate TB | 0.5–1 day | 15 minutes |
| Map to hierarchy | 1 day | 20–40 minutes |
| Build databook | 1–2 days | 5 minutes plus review |
| Find adjustment candidates | 1–2 days | 1 hour plus review |
| Bridge, NWC, KPIs | 1 day | 10 minutes |
| Management questions draft | 0.5 day | 15 minutes plus editing |
| First-draft commentary | 2–3 days | 1 hour plus editing |

The judgement time (deciding adjustments, interpreting NWC, writing the parts of the report that matter) is unchanged. It is just no longer the tail end of a week of building.

## What to be careful about

- **Data handling.** Know exactly what leaves the machine, where it goes and whether it is retained. Mask entity names if the engagement requires it. For regulated clients, route model calls through the firm's own cloud tenancy.
- **Traceability.** If a number in the report cannot be traced to a cell in the databook, the automation has failed regardless of how good the prose is.
- **Over-trust.** A ranked list of candidates is not a list of adjustments. Treat generated commentary as a first draft from a capable junior who has not been on the management call.

ZAF Tools is one implementation of this architecture, built as an Excel add-in with the six stages as ribbon buttons. [See how each stage works.](/features)
