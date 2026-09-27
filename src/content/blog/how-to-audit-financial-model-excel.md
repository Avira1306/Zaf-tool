---
title: "How to Audit a Financial Model in Excel: Checklist"
description: "Step-by-step method to audit a financial model in Excel: structure, formula consistency, hardcodes, references and tie-outs, with a 25-point checklist."
date: 2026-02-28
updated: 2026-09-02
category: Financial modelling
image: /img/pl-commentary.webp
imageAlt: A P&L schedule in Excel with review commentary beside it
---

A financial model audit is not a hunt for typos. It is a structured check that the model does what its author claims, that the numbers tie to their sources, and that a reviewer can follow the logic without the author in the room. Done well it takes an hour on a mid-sized databook. Done badly it takes a day and still misses the error that matters.

This is the method we use on FDD databooks before they go to a partner or a client, in the order we do it.

## Start with structure, not cells

Open the workbook and do nothing for five minutes except look at how it is organised.

- **Sheet order.** Inputs, calculations, outputs, in that order, left to right. A model that interleaves them is harder to audit and more likely to contain circularity.
- **Sheet naming.** A reviewer should know what a sheet contains from the tab. `PL1`, `BS1`, `NWC`, `ND` beat `Sheet21`.
- **Cover and index.** Is there a cover with the version, date and author, and an index sheet with hyperlinks? If not, add one before the audit; it is the map you will use for the next hour.
- **Colour convention.** Blue for inputs, black for formulas, green for cross-sheet links is the convention most finance teams use. Check whether the model follows one at all.

If the structure is poor, note it as a finding. Structural problems produce formula problems later.

## Map the formulas

Before checking any individual formula, colour the whole sheet by formula type. In Excel you can do this manually with Go To Special (F5 → Special → Formulas, then Constants), or with an add-in that does it in one click. What you want to see is blocks of the same colour: a row of formulas that stays a formula all the way across, a column of inputs that stays an input all the way down.

What you are looking for:

- A single hardcode in a row of formulas. This is the most common and most damaging error in financial models. Someone overwrote a formula with a number to "fix" it and never came back.
- A formula in a row of inputs. Usually harmless, sometimes a sign that an input has been linked to somewhere unexpected.
- Cross-sheet links in the middle of a calculation block. These are where broken references live after a sheet is renamed or deleted.

## Check formula consistency across rows and columns

Switch to R1C1 reference style (File → Options → Formulas) for this step. In R1C1, a formula that has been correctly filled across a row shows the same text in every cell. Any cell that differs is either a deliberate exception or an error, and you can find the differences by eye or with a simple `=IF(FORMULATEXT(B5)=FORMULATEXT(C5),"","DIFF")` helper row.

Common findings:

- A SUM range that stops one row short after someone inserted a line.
- A growth formula that references the wrong prior period in one column.
- An IFERROR wrapper on one cell that hides a #DIV/0! that should have been investigated.

## Hunt for hardcoded values

The formula map shows you the obvious ones. The dangerous ones are hidden inside formulas: `=B5*1.05`, `=SUM(C10:C20)+150`, `=D8/12*11.5`. Search the sheet for formulas containing digits other than 0 and 1 (Find → `*[2-9]*` with "Look in: Formulas" is a crude but effective start). Every embedded number should either be moved to an input cell or documented in a comment.

## Trace references and check for errors

- Run Excel's Error Checking (Formulas → Error Checking) and resolve every #REF!, #N/A, #VALUE! and #DIV/0!, or document why it is acceptable.
- Check for external links (Data → Edit Links). A databook should not depend on a file on someone's desktop.
- Check for circular references (the status bar shows "Circular References" if any exist). Interest calculations are the usual culprit; if the circularity is intentional, it needs an iteration switch and a note.
- Trace precedents on any output that feeds the report. The chain should end at an input or a source sheet, not at a hardcode.

## Tie out to source

This is the step most model audits skip, and it is the one that catches material errors.

- **P&L to trial balance.** Revenue, EBITDA and net income for each period should equal the mapped TB totals. A SUMIFS check row on each schedule, with a Variance line that shows zero, is the standard approach.
- **Balance sheet balances.** Total assets minus total liabilities and equity equals zero in every period. If it does not, stop; nothing downstream is reliable.
- **Cash flow to balance sheet.** Closing cash on the cash flow statement equals cash on the balance sheet.
- **Working capital to balance sheet.** Each NWC line reconciles to the corresponding balance sheet account.
- **Bridge to P&L.** An EBITDA bridge should close to the P&L EBITDA of the later period, with a variance of exactly zero.

Every one of these should be a visible check cell that says TIE (or shows the variance) on the face of the schedule. A reviewer should not have to build the check.

## Presentation and hygiene

Finally, the things that make a model look unreliable even when it is not:

- Consistent number formats: one decimal place, brackets for negatives, thousands separators, units stated in the header.
- Frozen panes on every schedule, set at the header row and label column.
- No stray content in far-right columns or far-down rows (Ctrl+End should land near the real end of the data).
- Groups collapsed, filters cleared, every sheet scrolled to A1, zoom set consistently. This is the "ready to send" state.
- Hidden sheets and very hidden sheets reviewed. If they exist, the reviewer needs to know why.

## The 25-point checklist

The full list we work through, in order:

| Area | Check |
|---|---|
| Structure | Inputs, calculations and outputs are separated |
| Structure | Every sheet is named for its content |
| Structure | Cover sheet with version, date, author |
| Structure | Index sheet with links |
| Structure | Colour convention applied |
| Formulas | Formula map shows clean blocks |
| Formulas | No hardcodes in formula rows |
| Formulas | Row-wise formula consistency (R1C1) |
| Formulas | Column-wise formula consistency |
| Formulas | No embedded constants in formulas |
| Formulas | No unexplained IFERROR wrappers |
| References | No #REF!, #N/A, #VALUE!, #DIV/0! |
| References | No external links |
| References | Circularities documented or removed |
| References | Named ranges valid and used |
| Tie-outs | P&L ties to TB in every period |
| Tie-outs | Balance sheet balances in every period |
| Tie-outs | Cash flow closing cash ties to BS |
| Tie-outs | NWC lines tie to BS |
| Tie-outs | Bridge closes to P&L |
| Presentation | Consistent number formats and units |
| Presentation | Frozen panes on every schedule |
| Presentation | No stray content beyond the data |
| Presentation | Groups closed, filters cleared, A1 selected |
| Presentation | Hidden sheets reviewed |

## Automating the mechanical half

Steps two through five are mechanical and can be automated. The ZAF Tools ribbon runs a formula map, a consistency and hardcode audit with a clickable scorecard, and a Reset View that handles the presentation hygiene, in about thirty seconds on a typical databook. The tie-out checks are built into every schedule that ZAF generates. The structural review and the judgement about what to do with the findings remain a human job, which is where the reviewer's hour should be spent. [See the model audit features.](/features/model-audit)

If you want the checklist as a spreadsheet with owner and status columns, it is included in the [financial due diligence checklist template](/fdd-templates/financial-due-diligence-checklist).
