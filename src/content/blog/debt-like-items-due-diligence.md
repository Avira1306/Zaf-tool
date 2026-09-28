---
title: "Debt-Like Items in Due Diligence: The Complete List, with Examples"
description: "What counts as a debt-like item, the tests buyers apply, a complete list grouped by type, and a worked Excel example from enterprise value to equity."
date: 2026-10-20
category: Debt & NWC
image: /img/net-debt-debt-like-items-example.webp
imageAlt: Excel net debt schedule listing debt-like items with agreed and disputed status and an EV to equity bridge
---

**Debt-like items** are obligations that are not formal borrowings but that a buyer treats like debt. They are deducted from enterprise value to reach the equity price, because they will need cash after completion for something the buyer is not getting value from.

Two deals can have the same enterprise value and the same EBITDA multiple, yet one seller receives a very different amount from the other. The difference is usually not the headline price. It is the list of items between enterprise value and equity: net debt, the working capital adjustment, and debt-like items. Of those three, debt-like items are the least standardised and the most negotiated. This guide gives you the tests, the complete list, and a worked example you can rebuild in Excel.

## Where debt-like items sit in the price

Most deals are priced on a cash-free, debt-free basis. The buyer agrees an enterprise value, usually a multiple of adjusted EBITDA, and then walks it down to the equity price:

1. **Enterprise value** (headline price)
2. **Less net financial debt**: borrowings and leases, less cash
3. **Less debt-like items**
4. **Plus or minus working capital** against the agreed peg
5. **Equals equity value** payable to the seller

Our [EV to equity bridge template](/fdd-templates/ev-to-equity-bridge) lays out these steps. The key point is that every dollar agreed as debt-like reduces the price by one dollar. On a 6x deal, finding $500k of debt-like items is worth as much to the buyer as finding about $83k of EBITDA adjustments. That is why this part of the report gets read line by line.

## The tests: is it debt-like?

There is no accounting standard for debt-like items. They are agreed in the SPA after negotiation. In practice, buyers apply four questions:

- **Will it cost cash after completion?** If paying it will use the buyer's cash, it is a candidate.
- **Does it relate to the period before completion?** Bonuses earned last year, tax on last year's profits, and a claim over a past event all belong to the seller's period.
- **Is it outside normal working capital?** Trade creditors that are paid on normal terms belong in NWC. An overdue VAT balance does not.
- **Is it already reflected in EBITDA?** If the cost has been normalised out of EBITDA and so not priced into the multiple, the liability usually belongs in the equity bridge.

Two consistency rules stop double counting. First, an item cannot sit in the working capital peg and in net debt at the same time. If holiday pay accruals are in the NWC definition, they are not also debt-like (see our [NWC peg guide](/blog/net-working-capital-peg-due-diligence)). Second, the treatment has to match EBITDA. If lease costs are excluded from EBITDA under IFRS 16, the lease liability belongs in net debt. If EBITDA is stated after rent, it does not. The same logic applies to [EBITDA adjustments](/blog/ebitda-adjustments-quality-of-earnings): if a one-off cost is added back to EBITDA but still unpaid at completion, expect the related liability to be argued as debt-like.

## The complete list

Each item has a tag: **usually** (buyers expect it and sellers rarely win), **often argued**, or **depends** (on the facts and the deal basis).

### Financing-type items
- **Lease liabilities** (depends): in net debt if EBITDA is stated before lease costs, as under IFRS 16 or Ind AS 116.
- **Shareholder and related-party loans** (usually): typically settled or waived at completion.
- **Accrued interest and break costs** (usually): interest to completion plus any prepayment penalty.
- **Declared but unpaid dividends** (usually).
- **Invoice discounting and factoring** (often argued): cash received early for receivables is borrowing in substance.
- **Supplier finance and reverse factoring** (often argued): payables extended by a bank arrangement look like trade creditors but behave like debt.
- **Overdrafts netted within creditors** (usually): find these during mapping, not at signing.

### Deferred and overdue obligations
- **Deferred consideration and earn-outs** from past acquisitions (usually).
- **Unpaid capex creditors** (usually): the buyer should not pay twice for assets already reflected in the price.
- **Overdue payables** beyond normal terms (often argued): a seller can raise completion cash by stretching creditors.
- **Deferred revenue and customer deposits** (often argued): buyers argue at least the unfunded cost to deliver is debt-like, while sellers argue it is normal working capital.
- **Deferred rent and lease incentives** (depends).

### People
- **Accrued bonuses and commissions** for the pre-completion period, plus employer taxes (usually).
- **Unfunded defined benefit pension deficits**, usually net of tax relief (often argued).
- **Committed redundancy and restructuring costs** (usually).
- **Holiday pay accruals** (depends): often in NWC instead.
- **Management incentive plan cash-outs** triggered by the sale (usually).

### Tax
- **Corporate tax payable** for pre-completion periods (usually).
- **Deferred or overdue VAT/GST and payroll taxes**, including government deferral schemes (usually).
- **Known tax exposures** (depends): often handled through an indemnity instead of price.

### Provisions and contingencies
- **Legal claims and settlements** (often argued).
- **Onerous contracts** (often argued).
- **Dilapidations and asset retirement obligations** (depends).
- **Environmental provisions** (depends).
- **Warranty provisions** above run-rate (often argued).

### Transaction-related
- **Deal fees borne by the target**: legal, advisory and vendor due diligence fees (usually).
- **Transaction and change-of-control bonuses** (usually).

### Cash-like items (the other side of the bridge)
A complete list includes the items that increase equity value or reduce available cash:
- **Trapped or restricted cash**: cash in overseas subsidiaries that cannot be freely paid out, or cash held as deposits (reduces cash).
- **Minimum operating cash** the business needs on the day (often argued, reduces cash).
- **Tax refunds receivable** for pre-completion periods (argued as cash-like by sellers).
- **Deposits and escrow balances recoverable** after completion.

### India: gratuity and leave encashment
For Indian targets, two employee liabilities appear on almost every deal:
- **Gratuity.** Under the Code on Social Security, 2020 (which replaced the Payment of Gratuity Act, 1972), employees generally qualify for gratuity after five years of continuous service, and fixed-term employees qualify pro rata after one year. The Code's wider definition of wages can also increase the liability, so check that the actuarial valuation reflects it. The unfunded part of the actuarial liability (the obligation less any plan assets, such as a group gratuity fund) is usually treated as debt-like. Smaller companies sometimes account for gratuity on a cash basis, so the liability may not be on the trial balance at all and diligence has to estimate it.
- **Leave encashment.** Accrued leave that employees can encash is a cash obligation. The long-term portion is often argued as debt-like, while the short-term portion may sit in working capital. Agree which, and keep it out of both.

## Worked example

![Excel net debt schedule listing debt-like items with agreed and disputed status and an EV to equity bridge](/img/net-debt-debt-like-items-example.webp)

The table shows a fictional target priced at 6.0x adjusted EBITDA of $5.0m, an enterprise value of $30.0m.

**Reported net debt is $4.2m**: a term loan and drawn revolver of $5.0m, plus leases of $0.65m, less cash of $1.45m. Most sellers' models stop here.

**Agreed debt-like items add $2.62m.** These are the "usually" items: pre-completion bonuses, tax payable, deferred VAT, deferred consideration on a 2024 acquisition, unpaid capex creditors and transaction bonuses. Trapped cash of $0.15m in an overseas subsidiary is included too, because the buyer cannot use it. The equity value on the seller's view is $23.18m.

**Disputed items total $1.34m**: a pension deficit, deferred revenue with unfunded delivery costs, and a dilapidations provision. If the buyer wins every point, equity falls to $21.84m. That $1.34m gap is the negotiation, and it is about 4.5% of enterprise value.

**Holiday pay is excluded** because it is already in the NWC peg. Counting it twice would be an error.

The status column matters as much as the amounts. A good schedule shows the deal team which items are settled, which are open, and what each side's argument is, so negotiation time goes to the disputed items only. Our [net debt and debt-like items template](/fdd-templates/net-debt-schedule) uses the same layout.

## How to find them in the numbers

Debt-like items rarely have their own line in the trial balance. They hide in other creditors, accruals, provisions and sometimes in trade payables. Places to look:

- **The balance sheet mapping.** Other creditors, accruals and provisions need account-level detail, not the reported line.
- **Subsequent events.** Payments after the balance sheet date often reveal what the accruals were for.
- **Board minutes and legal letters** for claims and restructuring decisions.
- **The tax computation and returns** for payable balances and deferrals.
- **Employment contracts and bonus schemes** for accrued and transaction-triggered payments.
- **Financing and supplier agreements** for factoring, reverse factoring and change-of-control clauses.
- **The draft SPA** for the definitions the lawyers are already using.

The practical fix is to tag every balance sheet account during mapping as NWC, net debt, debt-like or excluded. Once each account carries a tag, the NWC schedule, the net debt schedule and the equity bridge all reconcile to the trial balance, and moving an account from one category to another updates every schedule at once. ZAF Tools builds the [working capital and net debt schedules](/features/working-capital) this way from the mapped trial balance, so a reclassification agreed during negotiation flows through every schedule without rebuilding anything.

## FAQ

**What is the difference between net debt and debt-like items?**
Net debt covers financial borrowings and leases less cash. Debt-like items are other obligations that behave like debt, such as unpaid tax, bonuses or deferred consideration. Both are deducted from enterprise value.

**Are leases debt-like items?**
It depends on EBITDA. If lease costs are excluded from EBITDA (IFRS 16 or Ind AS 116 basis), lease liabilities belong in net debt. If EBITDA is stated after rent, they do not.

**Is deferred revenue a debt-like item?**
It is one of the most argued items. Buyers often treat at least the unfunded cost of delivering the service as debt-like. Sellers argue it is part of normal working capital.

**Who decides what is debt-like?**
The SPA does, after negotiation. Diligence sets out the candidates and the arguments on each side, and the deal team agrees the final list.

## Book a demo

If your team builds net debt and working capital schedules by hand, see ZAF Tools tag, map and reconcile them from the trial balance on a live demo. [Book a demo](/start-trial?type=demo).
