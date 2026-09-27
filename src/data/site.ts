export const SITE = {
  name: 'ZAF Tools',
  url: 'https://www.zaftool.com',
  tagline: 'AI financial due diligence, inside Excel',
  description:
    'ZAF Tools is an Excel add-in that runs financial due diligence end to end: import the trial balance, build financial statements, run Quality of Earnings, EBITDA bridge and working capital analysis, and export FDD commentary to Word. Built for M&A boutiques, PE deal teams and transaction advisory firms.',
  email: 'abhishek.bhandari@zaftool.com',
  supportEmail: 'support@zaftool.com',
  linkedin: 'https://linkedin.com/in/abhishek-bhandari',
  // No public download. Trial requests go to the form; the installer is emailed after signup/payment.
  trialUrl: '/start-trial',
  demoUrl: '/start-trial?type=demo',
  // TODO(Abhishek): paste a Formspree (or similar) form endpoint here. Until then the form falls back to email.
  formEndpoint: '',
  // TODO(Abhishek): paste Razorpay Payment Links (INR) and USD payment links here.
  payLinks: {
    soloINR: '#razorpay-solo-inr',
    proINR: '#razorpay-pro-inr',
    soloUSD: '#pay-solo-usd',
    proUSD: '#pay-pro-usd',
  },
  version: '5.0.6',
  company: 'Four Aces Education Private Limited',
  founder: 'Abhishek Bhandari',
  founderBio:
    'Abhishek Bhandari is a financial due diligence practitioner with 15+ years in FDD and M&A advisory at EY and Grant Thornton, working on Nordic and DACH mandates. He founded ZAF Tools to automate the parts of an FDD engagement that do not need a human, and Zion Advisor, an offshore FDD and Quality of Earnings practice.',
  clients: ['Windy Street', 'BPS Analytics'],
  stats: [
    { n: '80%', l: 'less time on the Excel build' },
    { n: '150+', l: 'cross-border deals behind the product' },
    { n: '0', l: 'client data stored' },
    { n: '7', l: 'TB languages translated in-table' },
  ],
};

export type Feature = {
  slug: string;
  name: string;
  short: string; // one line for cards and nav
  title: string; // SEO title
  metaDescription: string;
  h1: string;
  intro: string;
  problem: string;
  how: string[]; // steps
  outputs: string[];
  image?: string;
  imageAlt?: string;
  faqs: { q: string; a: string }[];
  keywords: string[];
  related: string[];
};

export const features: Feature[] = [
  {
    slug: 'quality-of-earnings',
    name: 'Quality of Earnings',
    short: 'Normalise EBITDA and trace every adjustment to source, inside the databook.',
    title: 'Quality of Earnings Software in Excel | ZAF Tools',
    metaDescription:
      'Run Quality of Earnings in Excel: find candidate EBITDA adjustments, build the normalised EBITDA schedule and draft QoE commentary from your trial balance.',
    h1: 'Quality of Earnings analysis that stays in Excel',
    intro:
      'A QoE is a judgement exercise built on a mechanical one. ZAF Tools does the mechanical part: it scans the P&L and general ledger for one-offs, non-operating items and run-rate issues, proposes adjustments with the source reference, and builds the reported-to-adjusted EBITDA schedule. You keep the judgement.',
    problem:
      'Most QoE work is spent finding the numbers, not deciding about them. Analysts trawl account detail line by line, build the adjustments schedule by hand, then rewrite the same three paragraphs of commentary on every deal. Cloud QoE platforms promise to fix this, but they take the analysis out of Excel, where the databook and the reviewer actually live.',
    how: [
      'Import the trial balance or general ledger and let AI Map suggest the chart of accounts mapping.',
      'Run Find Adjustments on any sheet. Each candidate comes with the account, the period, the amount and the reason it was flagged.',
      'Accept, reject or edit candidates. Accepted items flow into the Adjusted EBITDA schedule with a live tie-out to the reported P&L.',
      'Generate QoE commentary beside the schedule, or open the full report in Word.',
    ],
    outputs: [
      'Reported-to-adjusted EBITDA schedule by period',
      'Adjustments log with source references and status',
      'Run-rate and pro forma views',
      'QoE commentary in your house style',
    ],
    image: '/img/pl-commentary.webp',
    imageAlt: 'ZAF Tools P&L schedule with AI-generated FDD commentary in Excel',
    faqs: [
      {
        q: 'Does ZAF Tools decide which adjustments are valid?',
        a: 'No. It proposes candidates with evidence. The reviewer accepts or rejects each one, and only accepted items enter the adjusted EBITDA schedule.',
      },
      {
        q: 'Can it work from a general ledger rather than a trial balance?',
        a: 'Yes. Import either. GL-level detail gives Find Adjustments more to work with, especially for one-off and related-party items.',
      },
      {
        q: 'Does the QoE output match my firm’s format?',
        a: 'House Style captures your firm’s formatting once and applies it to every schedule and commentary block.',
      },
    ],
    keywords: ['quality of earnings software', 'QoE analysis Excel', 'EBITDA adjustments', 'normalised EBITDA'],
    related: ['ebitda-bridge', 'find-adjustments', 'fdd-commentary'],
  },
  {
    slug: 'ebitda-bridge',
    name: 'EBITDA Bridge',
    short: 'Period-to-period bridge with waterfall chart and a cross-check to the P&L.',
    title: 'EBITDA Bridge in Excel with Waterfall Chart | ZAF Tools',
    metaDescription:
      'Build an EBITDA bridge in Excel in one click: movement by revenue, COGS and opex, a waterfall chart, and a cross-check that ties the bridge to the P&L.',
    h1: 'EBITDA bridge, built and tied out in one click',
    intro:
      'Select the periods, and ZAF Tools builds the bridge schedule, decomposes the movement into revenue, cost of sales and operating expense drivers, draws the waterfall and adds a cross-check line so the closing EBITDA reconciles to the P&L to the decimal.',
    problem:
      'Bridges are rebuilt on every deal, usually from a template someone made years ago. They break when periods change, the chart needs manual relabelling, and nobody checks the closing figure against the P&L until the partner does.',
    how: [
      'Choose the opening and closing periods (FY, YTD or LTM).',
      'ZAF reads the mapped P&L and calculates each driver’s contribution.',
      'The bridge schedule and waterfall chart are written to a new sheet in your house style.',
      'A cross-check row compares bridge closing EBITDA to the P&L and shows TIE or the variance.',
    ],
    outputs: [
      'Bridge schedule with drivers per period',
      'Waterfall chart, labelled and formatted',
      'Cross-check to P&L with variance',
      'Optional commentary on the main movements',
    ],
    image: '/img/ebitda-bridge.webp',
    imageAlt: 'EBITDA bridge schedule and waterfall chart generated by ZAF Tools in Excel',
    faqs: [
      { q: 'Can I add my own bridge categories?', a: 'Yes. Drivers follow your mapping, so any grouping in your chart of accounts can become a bridge step.' },
      { q: 'Does it handle LTM and stub periods?', a: 'Yes. FY, YTD and LTM periods are all supported, including comparatives.' },
    ],
    keywords: ['EBITDA bridge Excel', 'EBITDA bridge template', 'waterfall chart EBITDA'],
    related: ['quality-of-earnings', 'build-financial-statements', 'working-capital'],
  },
  {
    slug: 'trial-balance-mapping',
    name: 'Trial balance mapping',
    short: 'Import any TB, translate it, and let AI suggest the mapping to your hierarchy.',
    title: 'Trial Balance Mapping Tool for FDD | ZAF Tools',
    metaDescription:
      'Map a trial balance to your FDD hierarchy in minutes: import, translate, AI-suggested mapping, unmapped-code checks, and refresh when a later TB arrives.',
    h1: 'Trial balance mapping without the spreadsheet archaeology',
    intro:
      'Every engagement starts with a trial balance in someone else’s chart of accounts, often in another language. ZAF Tools imports it, translates descriptions to English, scans the structure and proposes a mapping to your reporting hierarchy. You amend what it got wrong and move on.',
    problem:
      'Mapping is the least glamorous and most error-prone part of FDD. A miscoded account distorts every schedule downstream, and nobody finds it until the balance sheet does not balance.',
    how: [
      'Import the TB (Excel, CSV or from a PDF via Import PDF).',
      'Translate TB converts non-English account descriptions.',
      'Scan TB checks structure, duplicates and sign conventions.',
      'AI Map suggests hierarchy codes; Amend Mapping fixes exceptions; Refresh Missing TB Codes catches anything new when a later TB arrives.',
    ],
    outputs: [
      'Mapped TB with hierarchy codes',
      'Exceptions list of unmapped or ambiguous accounts',
      'Reusable hierarchy mapping template per client',
      'Group consolidation across entities',
    ],
    image: '/img/nwc-schedule.webp',
    imageAlt: 'Working capital schedule in ZAF Tools showing mapped trial balance codes',
    faqs: [
      { q: 'Can I reuse a mapping on the next deal?', a: 'Yes. Export Hierarchy Template saves the mapping; Import Hierarchy Mapping applies it to a new TB.' },
      { q: 'What about multi-entity groups?', a: 'Group Consolidation maps each entity’s TB and consolidates into one set of statements.' },
    ],
    keywords: ['trial balance mapping', 'TB mapping tool', 'chart of accounts mapping Excel'],
    related: ['build-financial-statements', 'working-capital', 'quality-of-earnings'],
  },
  {
    slug: 'build-financial-statements',
    name: 'Build financial statements',
    short: 'From mapped TB to P&L, balance sheet, NWC, net debt and cash flow schedules.',
    title: 'Build FDD Financial Statements from a Trial Balance | ZAF Tools',
    metaDescription:
      'Turn a mapped trial balance into a full FDD databook: P&L, balance sheet, NWC, net debt and cash flow with KPIs and cross-checks, in your house style.',
    h1: 'Financial statements built from the trial balance, not retyped from a PDF',
    intro:
      'Run Full FDD takes a mapped trial balance and produces the databook: P&L, balance sheet, net working capital, net debt and cash flow schedules with KPIs, monthly and annual views, and source checks back to the TB on every sheet.',
    problem:
      'Databooks are assembled by hand, one SUMIFS at a time. Monthly views drift from annual views. A late TB means rebuilding half the file.',
    how: [
      'Set the style theme or capture your firm’s House Style once.',
      'Run Full FDD builds every statement from the mapped TB.',
      'Update TB adds a later period and refreshes every schedule.',
      'The dashboard summarises revenue, EBITDA, margin, net debt and NWC with a rule-based deal health scorecard.',
    ],
    outputs: [
      'P&L, BS, NWC, net debt and cash flow schedules',
      'Monthly and annual views with LTM',
      'KPIs and ratios (DSO, DIO, DPO, cash conversion)',
      'Financial dashboard with scorecard and action centre',
    ],
    image: '/img/dashboard.webp',
    imageAlt: 'ZAF Tools financial dashboard showing revenue, EBITDA, net debt and working capital KPIs',
    faqs: [
      { q: 'Are the outputs formulas or values?', a: 'Formulas. Every schedule is live-linked to the mapped TB so reviewers can trace any number.' },
      { q: 'Can I mask client data before sending externally?', a: 'Yes. Data Masking replaces entity names and identifiers before export.' },
    ],
    keywords: ['FDD databook', 'financial statements from trial balance', 'due diligence databook Excel'],
    related: ['trial-balance-mapping', 'working-capital', 'ebitda-bridge'],
  },
  {
    slug: 'working-capital',
    name: 'Working capital & net debt',
    short: 'Monthly NWC, DSO/DIO/DPO, seasonality and net debt schedules.',
    title: 'Net Working Capital Analysis for Due Diligence | ZAF Tools',
    metaDescription:
      'Analyse net working capital and net debt in Excel: monthly NWC schedules, DSO, DIO, DPO, cash conversion cycle and peg analysis from the trial balance.',
    h1: 'Working capital analysis with the monthly detail buyers actually negotiate on',
    intro:
      'ZAF Tools builds the NWC schedule at monthly granularity, calculates DSO, DIO, DPO and cash conversion cycle, shows reported max, min and swing, and reconciles each month back to the balance sheet.',
    problem:
      'The NWC peg is where deals are won or lost, and it is usually supported by a schedule someone built at 2am. Seasonality gets missed, non-trade items get lumped in, and the reconciliation to the balance sheet is an afterthought.',
    how: [
      'NWC items are identified from the mapping (trade, other, non-trade).',
      'Monthly schedule is built with KPIs per month and per period.',
      'Source check compares each month to the balance sheet.',
      'Analyse Working Capital drafts commentary on trends, seasonality and peg considerations.',
    ],
    outputs: [
      'Monthly NWC schedule with trade and other splits',
      'DSO, DIO, DPO, cash conversion cycle',
      'Reported max, min and swing',
      'Net debt and debt-like items schedule',
    ],
    image: '/img/nwc-schedule.webp',
    imageAlt: 'Monthly working capital schedule with DSO, DIO and DPO in ZAF Tools',
    faqs: [
      { q: 'Does it calculate an NWC peg?', a: 'It builds the LTM average and seasonality views that support a peg; the final number remains the deal team’s call.' },
    ],
    keywords: ['net working capital due diligence', 'NWC analysis Excel', 'DSO DIO DPO calculation'],
    related: ['build-financial-statements', 'quality-of-earnings', 'fdd-commentary'],
  },
  {
    slug: 'deal-document-analysis',
    name: 'Deal document analysis',
    short: 'CIMs, transcripts and data-room PDFs, triaged and turned into questions.',
    title: 'AI CIM and Deal Document Analysis in Excel | ZAF Tools',
    metaDescription:
      'Analyse CIMs, call transcripts and data-room documents with AI inside Excel: triage files, extract what matters and generate management questions.',
    h1: 'Read the CIM once. Let the add-in read it a second time.',
    intro:
      'Doc Triage ranks data-room documents by relevance. Deal Documents extracts the financial claims, KPIs and caveats from a CIM or transcript. Management Questions turns gaps between the documents and the numbers into a question list, logged and tracked.',
    problem:
      'Data rooms have hundreds of files. The information you need is in twelve of them, and the questions you should ask are in the gaps between what management said and what the TB shows.',
    how: [
      'Point Doc Triage at a folder of PDFs; it ranks them for FDD relevance.',
      'Run Deal Documents on the CIM or a call transcript to extract claims and figures.',
      'Generate Management Questions from any schedule; each question cites the figure that prompted it.',
      'Track questions in the MQ log until answered.',
    ],
    outputs: [
      'Ranked document list with relevance notes',
      'Extracted claims table with source page',
      'Management question list with references',
      'Deal Brief summary page',
    ],
    faqs: [
      { q: 'Is document content sent to the cloud?', a: 'Yes, to the ZAF backend for analysis. Use Data Masking first if the engagement requires it, and see the security page for details.' },
    ],
    keywords: ['CIM analysis AI', 'management questions due diligence', 'data room document analysis'],
    related: ['fdd-commentary', 'quality-of-earnings', 'pdf-to-excel'],
  },
  {
    slug: 'fdd-commentary',
    name: 'FDD commentary & export',
    short: 'Commentary beside the schedule, partner-grade rewrite, export to Word and PowerPoint.',
    title: 'AI FDD Commentary and Report Export from Excel | ZAF Tools',
    metaDescription:
      'Generate FDD commentary beside any schedule and export to Word or PowerPoint: P&L, balance sheet, NWC and cash flow commentary in your house style.',
    h1: 'Commentary written from the numbers, next to the numbers',
    intro:
      'Select a schedule and FDD Commentary writes the headline, basis of preparation and driver analysis beside it, citing figures from the sheet. Partner Commentary enriches it with management’s explanations from your notes. Export sends table, commentary or both to Word or PowerPoint.',
    problem:
      'Commentary is where FDD hours go. The first draft is formulaic and the numbers get retyped, so figures in the report drift from the databook.',
    how: [
      'Select the schedule and choose commentary length.',
      'FDD Commentary drafts beside the selection, quoting the sheet’s figures.',
      'Add management explanations; Partner Commentary integrates them.',
      'Export to Word, PowerPoint or PDF, multi-sheet if needed.',
    ],
    outputs: [
      'Headline, basis of preparation and driver commentary',
      'Partner-grade enriched version',
      'Word report with tables and text',
      'PowerPoint slides per schedule',
    ],
    image: '/img/pl-commentary.webp',
    imageAlt: 'FDD commentary generated beside a P&L schedule in Excel',
    faqs: [
      { q: 'Can I control tone and length?', a: 'Yes. Commentary length is a setting, and House Style captures your firm’s phrasing conventions.' },
      { q: 'Does it invent numbers?', a: 'Commentary quotes figures from the selected sheet. Every figure in the text can be traced to a cell.' },
    ],
    keywords: ['FDD report automation', 'due diligence commentary AI', 'Excel to Word report'],
    related: ['quality-of-earnings', 'deal-document-analysis', 'build-financial-statements'],
  },
  {
    slug: 'find-adjustments',
    name: 'Find adjustments & anomalies',
    short: 'AI scans any sheet for one-offs, outliers and inconsistencies.',
    title: 'Find EBITDA Adjustments and Data Anomalies in Excel | ZAF Tools',
    metaDescription:
      'AI-assisted detection of EBITDA adjustments, one-off items and data anomalies in any Excel sheet. ZAF Tools flags candidates with reasons so reviewers decide faster.',
    h1: 'Find the one-offs before the buyer’s advisor does',
    intro:
      'Find Adjustments and Find Anomalies work on any sheet, not only ZAF-built ones. They scan for spikes, sign flips, round-number entries, related-party patterns and items that break run-rate, and list them with the reason.',
    problem:
      'Anomalies hide in monthly detail. Manual scanning is slow, and the ones that matter are often small relative to the total.',
    how: [
      'Select a range or a whole sheet.',
      'Run Find Adjustments (EBITDA focus) or Find Anomalies (data quality focus).',
      'Review the ranked list with reasons and cell references.',
      'Push accepted adjustments to the QoE schedule.',
    ],
    outputs: ['Ranked candidate list with reasons', 'Cell references for every item', 'Direct link into the QoE schedule'],
    faqs: [{ q: 'Does it work on a client’s own workbook?', a: 'Yes. Both tools run on any range in any workbook.' }],
    keywords: ['EBITDA add-backs', 'find one-off items', 'data anomaly detection Excel'],
    related: ['quality-of-earnings', 'model-audit', 'fdd-commentary'],
  },
  {
    slug: 'pdf-to-excel',
    name: 'PDF & image to Excel',
    short: 'Financial statements from scanned PDFs and images into clean tables.',
    title: 'Convert Financial Statement PDFs and Images to Excel | ZAF Tools',
    metaDescription:
      'Import financial statements from PDFs and images straight into Excel tables. Batch import whole data-room folders with ZAF Tools.',
    h1: 'Financial statements out of PDFs, without retyping',
    intro:
      'Import PDF and Image to Table read statutory accounts, management accounts and scanned schedules into structured tables. Batch PDF Import handles a folder at a time and writes an import index.',
    problem: 'Data rooms are full of PDFs. Retyping them is slow and introduces errors that surface weeks later.',
    how: ['Choose a file, image or folder.', 'ZAF extracts tables with headers and periods.', 'Review the import index and fix flagged cells.', 'Map and build statements from the imported data.'],
    outputs: ['Structured tables per document', 'PDF import index sheet', 'Batch import log'],
    faqs: [{ q: 'How accurate is extraction?', a: 'High on typed statements; scanned documents are flagged for a review pass. Always reconcile totals, which the import index makes quick.' }],
    keywords: ['PDF to Excel financial statements', 'extract tables from PDF Excel', 'image to table Excel'],
    related: ['trial-balance-mapping', 'deal-document-analysis', 'build-financial-statements'],
  },
  {
    slug: 'management-questions',
    name: 'Management questions',
    short: 'FDD-grade management questions generated from the active schedule, logged and tracked.',
    title: 'Due Diligence Management Questions Generator for Excel | ZAF Tools',
    metaDescription:
      'Generate financial due diligence management questions from any P&L, balance sheet or NWC schedule in Excel. Log, track and export the MQ list with ZAF Tools.',
    h1: 'Management questions, generated from the numbers',
    intro:
      'Mgmt Questions reads the active sheet, spots the movements, gaps and anomalies a reviewer would query, and writes FDD-grade questions for management. Every question lands in an MQ log with area, priority and status, so the list doubles as your tracker.',
    problem: 'Management question lists are written late, from memory, and miss the movements the schedules actually show. The same generic questions go out on every deal.',
    how: ['Open a P&L, balance sheet, NWC or revenue schedule.', 'Click Mgmt Questions on the ZAF AI ribbon.', 'Review, edit and prioritise the questions in the MQ log.', 'Export the list to Word or send it with the information request.'],
    outputs: ['Management questions tied to specific lines and periods', 'MQ log with area, priority and status', 'Exportable question list for management meetings'],
    faqs: [{ q: 'Are the questions generic?', a: 'No. They are written from the figures on the active sheet, so they reference the actual movements and periods. Run Full FDD generates them alongside statements and commentary.' }],
    keywords: ['due diligence management questions', 'FDD questions for management', 'due diligence question list'],
    related: ['fdd-commentary', 'deal-document-analysis', 'quality-of-earnings'],
  },
  {
    slug: 'group-consolidation',
    name: 'Group consolidation',
    short: 'Consolidate entity trial balances with intercompany eliminations, inside Excel.',
    title: 'Excel Consolidation Add-in with Intercompany Eliminations | ZAF Tools',
    metaDescription:
      'Consolidate multi-entity trial balances in Excel with intercompany eliminations. Group-level financial statements for due diligence, built by the ZAF Tools add-in.',
    h1: 'Group statements from entity trial balances',
    intro:
      'Group Consolidation combines mapped entity trial balances into group financial statements and applies intercompany eliminations, with an audit trail from each group line back to the entity accounts. Consolidate Files and Consolidate Sheets pull scattered workbooks together first.',
    problem: 'Multi-entity targets mean multiple trial balances, charts of accounts and currencies. Consolidating them by hand, and redoing it when a TB changes, is days of error-prone work.',
    how: ['Import and map each entity trial balance.', 'Translate non-English TBs in-table if needed.', 'Run Group Consolidation and review intercompany eliminations.', 'Build group P&L, balance sheet and cash flow from the consolidated flatfile.'],
    outputs: ['Consolidated group flatfile', 'Intercompany elimination schedule', 'Group financial statements with entity drill-down'],
    faqs: [{ q: 'Does it handle foreign-language trial balances?', a: 'Yes. Translate TB converts Swedish, German, Spanish, French, Dutch, Italian and Portuguese account names to English before mapping.' }],
    keywords: ['excel consolidation add-in', 'intercompany elimination excel', 'consolidate trial balances'],
    related: ['trial-balance-mapping', 'build-financial-statements', 'model-audit'],
  },
  {
    slug: 'excel-to-powerpoint-word',
    name: 'Export to PowerPoint, Word & PDF',
    short: 'Multi-sheet export to PowerPoint and Word with Excel formatting kept, plus cover and index.',
    title: 'Export Excel to PowerPoint and Word Reports | ZAF Tools Add-in',
    metaDescription:
      'Export Excel schedules to PowerPoint slides and Word reports with formatting intact, generate PDF packs, cover pages and sheet indexes. Built for FDD reporting.',
    h1: 'From databook to client-ready report in one click',
    intro:
      'Multi-sheet Export builds a PowerPoint deck with agenda and section slides and tables that keep their Excel formatting. Export to Word turns commentary into a formatted report. Export to PDF packs all visible sheets with auto-orientation, and Cover Page and Index finish the workbook.',
    problem: 'The last day of an FDD is spent pasting tables into slides, fixing fonts and rebuilding the report shell. It is the least valuable work on the engagement and the most error-prone.',
    how: ['Select the sheets to export.', 'Choose PowerPoint, Word or PDF.', 'ZAF builds agenda, section slides and formatted tables.', 'Add the cover page and index to the workbook for delivery.'],
    outputs: ['PowerPoint deck with agenda and section slides', 'Formatted Word FDD report', 'PDF pack of all visible sheets', 'Workbook cover page and sheet index'],
    faqs: [{ q: 'Do tables keep Excel formatting?', a: 'Yes. Number formats, bracketed negatives, header colours and bold totals carry over to PowerPoint and Word.' }],
    keywords: ['excel to powerpoint add-in', 'export excel to word report', 'excel to pdf all sheets'],
    related: ['fdd-commentary', 'build-financial-statements', 'model-audit'],
  },
  {
    slug: 'model-audit',
    name: '38 free Excel tools & model audit',
    short: 'Formula consistency, hardcodes, broken refs, plus 38 free formatting, navigation and cleaning tools.',
    title: 'Free Excel Add-in for Finance: 38 Tools + Model Audit | ZAF Tools',
    metaDescription:
      'Audit financial models for formula inconsistencies, hardcodes and broken references, plus 38 free one-click formatting, consolidation and navigation tools.',
    h1: 'The model audit and formatting toolkit, on the second ribbon tab',
    intro:
      'ZAF Tools ships two ribbons. ZAF AI runs the FDD workflow. ZAF Tools carries the utilities you use all day: Model Audit and Error Scan, Quick Map colour coding, Consolidate Sheets and Files, Flatfile, Concentration analysis, Clean Text, Fix Dates, Apply Font, Neg () Format and more: 38 tools, free, no subscription.',
    problem:
      'Reviewers still catch hardcodes and broken ranges by eye, and analysts still spend the last hour of every deliverable on formatting.',
    how: [
      'Quick Map colours formulas, hardcodes and cross-sheet links in one pass.',
      'Model Audit runs consistency, range, reference and hardcode checks with a clickable scorecard.',
      'Consolidate Files pulls a folder of monthly files into one workbook.',
      'Reset View prepares the file for sending: A1, groups closed, filters cleared.',
    ],
    outputs: ['Audit scorecard with links to every issue', 'Formula map', 'Consolidated workbook', 'Customer and revenue concentration analysis'],
    faqs: [{ q: 'Do the utilities need the AI subscription?', a: 'The ZAF Tools ribbon works offline. The ZAF AI ribbon uses the managed backend.' }],
    keywords: ['financial model audit software', 'Excel model audit add-in', 'Macabacus alternative'],
    related: ['find-adjustments', 'build-financial-statements', 'ebitda-bridge'],
  },
];

export const workflow = [
  { step: 'Import', text: 'Trial balance, GL or PDFs into Excel.', href: '/features/trial-balance-mapping' },
  { step: 'Map', text: 'AI suggests the hierarchy; you amend exceptions.', href: '/features/trial-balance-mapping' },
  { step: 'Build', text: 'P&L, BS, NWC, net debt and cash flow schedules.', href: '/features/build-financial-statements' },
  { step: 'Analyse', text: 'QoE, EBITDA bridge, working capital, anomalies.', href: '/features/quality-of-earnings' },
  { step: 'Question', text: 'Management questions from the gaps.', href: '/features/management-questions' },
  { step: 'Report', text: 'Commentary beside the numbers; export to Word.', href: '/features/fdd-commentary' },
];

export const pricing = {
  currencyNote: 'Prices in USD. INR billing available at checkout.',
  tiers: [
    {
      name: 'Solo',
      for: 'Individual FDD practitioners',
      usd: '$29',
      inr: '₹2,499',
      period: 'per month',
      features: [
        'Full P&L, balance sheet, NWC and cash flow analysis',
        'AI commentary on every statement',
        'Management questions generation',
        'Anomaly and Quality of Earnings detection',
        'Word and PowerPoint export',
        'Up to 13 full due diligence runs per month',
      ],
      cta: 'Buy Solo',
      href: 'solo',
      highlight: false,
    },
    {
      name: 'Pro',
      for: 'Transaction advisory teams',
      usd: '$189',
      inr: '₹15,999',
      period: 'per month',
      features: [
        'Everything in Solo',
        '5 seats for your team',
        'Advanced AI on every analysis',
        'Up to 68 full due diligence runs per month',
        'Priority processing',
        'Email support',
      ],
      cta: 'Buy Pro',
      href: 'pro',
      highlight: true,
    },
    {
      name: 'Enterprise',
      for: 'Big 4 and mid-tier firms',
      usd: 'Custom',
      inr: 'Custom',
      period: '',
      features: ['Everything in Pro', 'Unlimited seats', 'Dedicated onboarding', 'Custom workflows and house style', 'Corporate AI: your own Azure OpenAI endpoint', 'SLA-backed support'],
      cta: 'Talk to us',
      href: `mailto:${SITE.email}?subject=${encodeURIComponent('Enterprise inquiry - ZAF Tools')}`,
      highlight: false,
    },
  ],
};

export const faqs = [
  { q: 'Which Excel versions does ZAF Tools support?', a: 'Excel 2016, 2019, 2021 and Microsoft 365 on Windows. Mac support is on the roadmap.' },
  { q: 'Where does my data go?', a: 'The ZAF Tools ribbon (formatting, audit, consolidation) runs entirely on your machine. The ZAF AI ribbon sends the selected range or document to the ZAF backend for analysis and returns the result; nothing is stored beyond the request. Enterprise plans can route AI calls to the firm’s own Azure OpenAI endpoint via Corporate AI. Data Masking lets you anonymise entity names before any AI call.' },
  { q: 'Does it use VBA macros?', a: 'Yes. ZAF Tools is a code-signed .xlam add-in. Your IT team can verify the certificate and whitelist the publisher.' },
  { q: 'How does the free trial work?', a: 'Request a trial on the Start free trial page and we email you the signed installer and a licence within one business day. Use the full ZAF AI ribbon for 14 days. No card required. The ZAF Tools utility ribbon remains free to use afterwards.' },
  { q: 'What is the refund policy?', a: 'Paid plans carry a 14-day money-back guarantee. Email support and it is processed the same week.' },
  { q: 'Can I use it on more than one device?', a: 'A Solo seat covers one active device at a time. Pro includes five seats.' },
  { q: 'How do I get support?', a: 'Email support@zaftool.com or use Support in the Updates menu, which attaches a diagnostic bundle. Founder support is included on every plan.' },
];

export type Comparison = {
  slug: string;
  competitor: string;
  title: string;
  metaDescription: string;
  h1: string;
  summary: string;
  theirStrength: string;
  ourStrength: string;
  rows: { dim: string; zaf: string; them: string }[];
  verdict: string;
  keywords: string[];
};

export const comparisons: Comparison[] = [
  {
    slug: 'zaf-tools-vs-macabacus',
    competitor: 'Macabacus',
    title: 'ZAF Tools vs Macabacus: Excel Add-in Comparison (2026)',
    metaDescription:
      'Macabacus is a productivity and linking suite for bankers. ZAF Tools is an FDD workflow with AI analysis. Feature-by-feature comparison and who each is for.',
    h1: 'ZAF Tools vs Macabacus',
    summary:
      'Macabacus is the established productivity suite for investment bankers: formatting, model auditing, charting and Excel-to-PowerPoint linking across Office. ZAF Tools overlaps on the utility layer and then does something Macabacus does not attempt: it runs the financial due diligence analysis itself.',
    theirStrength:
      'Excel-to-PowerPoint linking, a large shortcut library, enterprise deployment and a fifteen-year track record. If your work is pitchbooks and linked decks, Macabacus is built for that.',
    ourStrength:
      'Trial balance import and AI mapping, financial statement build, Quality of Earnings, EBITDA bridge, working capital, management questions and commentary, all from inside Excel. Priced for boutiques and individual practitioners.',
    rows: [
      { dim: 'Primary job', zaf: 'Financial due diligence workflow with AI', them: 'Modelling productivity and Office linking' },
      { dim: 'Model audit', zaf: 'Yes (consistency, hardcodes, refs, scorecard)', them: 'Yes, extensive' },
      { dim: 'Excel to PowerPoint', zaf: 'Export schedules and commentary to slides', them: 'Live linking across Excel, PowerPoint, Word' },
      { dim: 'TB import and mapping', zaf: 'Yes, with AI mapping and translation', them: 'No' },
      { dim: 'Quality of Earnings', zaf: 'Yes', them: 'No' },
      { dim: 'EBITDA bridge', zaf: 'One-click with tie-out', them: 'Waterfall charting only' },
      { dim: 'AI commentary', zaf: 'Yes, beside the schedule', them: 'No' },
      { dim: 'Deployment', zaf: 'MSI, code-signed add-in', them: 'MSI, enterprise admin tools' },
      { dim: 'Platform', zaf: 'Windows Excel', them: 'Windows Excel (Mac limited)' },
      { dim: 'Entry price', zaf: '$29 per user per month', them: 'Contact sales; annual per seat' },
    ],
    verdict:
      'Choose Macabacus if your team’s output is linked pitchbooks and you want a mature shortcut layer across Office. Choose ZAF Tools if your team’s output is FDD databooks and reports and you want the analysis, not just the formatting, automated. Many boutiques run both.',
    keywords: ['Macabacus alternative', 'Macabacus vs', 'Macabacus pricing'],
  },
  {
    slug: 'zaf-tools-vs-upslide',
    competitor: 'UpSlide',
    title: 'ZAF Tools vs UpSlide: Which Fits a Deal Team? (2026)',
    metaDescription:
      'UpSlide automates documents and brand compliance for large institutions. ZAF Tools automates FDD analysis for boutiques and deal teams. Comparison and fit guide.',
    h1: 'ZAF Tools vs UpSlide',
    summary:
      'UpSlide is enterprise document automation: brand-compliant slides, Excel-to-PowerPoint linking, content libraries and Power BI integration for banks and Big 4 firms. ZAF Tools is a working tool for the analyst building the databook.',
    theirStrength: 'Brand compliance at scale, reliable linking, onboarding and customer success programs for large teams.',
    ourStrength: 'The FDD analysis itself, available to a single practitioner at $29 per month with no sales call.',
    rows: [
      { dim: 'Primary job', zaf: 'FDD analysis inside Excel', them: 'Document automation and brand compliance' },
      { dim: 'Target buyer', zaf: 'Boutiques, PE deal teams, individual practitioners', them: 'Enterprises with 5+ seats' },
      { dim: 'Quality of Earnings, bridge, NWC', zaf: 'Yes', them: 'No' },
      { dim: 'AI commentary', zaf: 'Yes', them: 'Slide-level AI assistance' },
      { dim: 'Excel to PowerPoint', zaf: 'Export', them: 'Live linking, library' },
      { dim: 'Pricing', zaf: 'Published, from $29', them: 'Custom enterprise' },
    ],
    verdict: 'Different layers of the stack. UpSlide polishes the deliverable; ZAF Tools produces the analysis that goes into it.',
    keywords: ['UpSlide alternative', 'UpSlide vs Macabacus'],
  },
  {
    slug: 'zaf-tools-vs-datasnipper',
    competitor: 'DataSnipper',
    title: 'ZAF Tools vs DataSnipper for Due Diligence (2026)',
    metaDescription:
      'DataSnipper is an audit-grade document tie-out tool. ZAF Tools is an FDD analysis workflow. When to use each, and where they overlap on PDF extraction.',
    h1: 'ZAF Tools vs DataSnipper',
    summary:
      'DataSnipper is built for auditors: snip figures from PDFs into Excel with a link back to the source page. ZAF Tools also extracts from PDFs, but its centre of gravity is what happens next: mapping, statements, QoE, bridge and commentary.',
    theirStrength: 'Audit-trail tie-outs, document matching, widespread adoption in audit teams.',
    ourStrength: 'Analysis. Once numbers are in Excel, ZAF builds and analyses the databook.',
    rows: [
      { dim: 'Primary job', zaf: 'FDD analysis', them: 'Document tie-out and evidence' },
      { dim: 'PDF extraction', zaf: 'Tables to Excel, batch folders', them: 'Snips with source link' },
      { dim: 'QoE and bridge', zaf: 'Yes', them: 'No' },
      { dim: 'AI commentary and questions', zaf: 'Yes', them: 'No' },
      { dim: 'Buyer', zaf: 'Transaction advisory', them: 'Audit and assurance' },
      { dim: 'Pricing', zaf: 'From $29 per month', them: 'Per seat, contact sales' },
    ],
    verdict: 'For statutory audit evidence, DataSnipper. For transaction diligence, ZAF Tools. Teams doing both often use both.',
    keywords: ['DataSnipper alternative', 'DataSnipper due diligence'],
  },
  {
    slug: 'zaf-tools-vs-daloopa',
    competitor: 'Daloopa',
    title: 'ZAF Tools vs Daloopa: Data Extraction vs FDD Analysis',
    metaDescription:
      'Daloopa supplies AI-cleaned historical data from public filings. ZAF Tools analyses private-company trial balances for due diligence. A comparison for deal teams.',
    h1: 'ZAF Tools vs Daloopa',
    summary:
      'Daloopa maintains a database of public-company financials and pushes them into models. ZAF Tools works on private targets, where there is no database, only a trial balance and a data room.',
    theirStrength: 'Public-company historicals with source links, model updates on earnings day.',
    ourStrength: 'Private-company FDD from raw TB and documents.',
    rows: [
      { dim: 'Data source', zaf: 'Client TB, GL, data-room PDFs', them: 'Public filings database' },
      { dim: 'Use case', zaf: 'M&A due diligence', them: 'Equity research, public comps' },
      { dim: 'QoE, bridge, NWC', zaf: 'Yes', them: 'No' },
      { dim: 'AI commentary', zaf: 'Yes', them: 'No' },
      { dim: 'Pricing', zaf: 'From $29 per month', them: 'Enterprise' },
    ],
    verdict: 'Not really competitors. Daloopa for public-company data, ZAF Tools for private-company diligence.',
    keywords: ['Daloopa alternative'],
  },
  {
    slug: 'zaf-tools-vs-ai-qoe-platforms',
    competitor: 'cloud QoE platforms',
    title: 'ZAF Tools vs Cloud AI QoE Platforms (Finsider, Keye, PinpointAI)',
    metaDescription:
      'Cloud AI QoE platforms upload your data room and return a draft report. ZAF Tools keeps the analysis in Excel where reviewers work. Trade-offs, pricing and fit.',
    h1: 'ZAF Tools vs cloud AI QoE platforms',
    summary:
      'A new category of platforms (Finsider, Keye, Termina, PinpointAI) ingests a data room and produces a draft QoE or FDD report. They are impressive and expensive, and they move the work out of Excel. ZAF Tools takes the opposite bet: the reviewer’s judgement lives in the databook, so the automation should too.',
    theirStrength: 'End-to-end drafts from raw documents, transaction-level analysis when a GL is available, polished web UI.',
    ourStrength: 'Every figure is a formula in your workbook. Adjustments are accepted cell by cell. Output matches your house style. Priced per analyst, not per engagement.',
    rows: [
      { dim: 'Where the work happens', zaf: 'Excel', them: 'Web platform' },
      { dim: 'Traceability', zaf: 'Live formulas to TB', them: 'Report with source references' },
      { dim: 'Reviewer control', zaf: 'Accept/reject each adjustment', them: 'Edit the draft' },
      { dim: 'House style', zaf: 'Captured and applied', them: 'Platform template' },
      { dim: 'Pricing', zaf: 'From $29 per user per month', them: 'Typically $25K+ per year or per engagement' },
      { dim: 'Data residency', zaf: 'Optional own Azure endpoint (Enterprise)', them: 'Vendor cloud' },
    ],
    verdict: 'If you want a first-draft report from a data room and have the budget, the platforms deliver. If you want your analysts faster in the tool they already use, ZAF Tools does that for the price of a lunch.',
    keywords: ['AI quality of earnings software', 'Finsider alternative', 'AI FDD platform'],
  },
];

export const personas = [
  {
    slug: 'ma-boutiques',
    name: 'M&A boutiques and transaction advisory firms',
    title: 'FDD Software for M&A Boutiques and Advisory Firms | ZAF Tools',
    metaDescription: 'Deliver Big 4-grade FDD databooks and reports with a small team. ZAF Tools automates TB mapping, statements, QoE and commentary inside Excel.',
    h1: 'Big 4 output from a boutique team',
    intro: 'Boutique advisory competes on speed and partner attention. ZAF Tools removes the analyst-hours that neither client nor partner sees: mapping, databook build, first-draft commentary.',
    pains: ['Every engagement starts from a blank databook', 'Senior time spent checking mapping and tie-outs', 'Commentary drafted from scratch under deadline', 'Enterprise tools priced for 50 seats, not 5'],
    gains: ['Databook from TB in an afternoon', 'Tie-outs and source checks on every schedule', 'First-draft commentary beside every statement', 'Pro plan: 5 seats for $189 per month'],
    features: ['trial-balance-mapping', 'build-financial-statements', 'quality-of-earnings', 'fdd-commentary'],
  },
  {
    slug: 'pe-deal-teams',
    name: 'Private equity deal teams',
    title: 'Due Diligence Tools for Private Equity Deal Teams | ZAF Tools',
    metaDescription: 'Run your own first-pass financial diligence in Excel before commissioning advisors. QoE, EBITDA bridge, working capital and management questions from the CIM and TB.',
    h1: 'First-pass diligence before you pay for a report',
    intro: 'Deal teams read the CIM, build a bridge and draft questions for management before advisors are engaged. ZAF Tools compresses that from days to hours and makes the eventual FDD scope sharper.',
    pains: ['CIM numbers retyped into a model', 'Bridge and NWC built from scratch per deal', 'Management questions drafted from memory', 'Advisor reports arrive too late to shape the thesis'],
    gains: ['CIM extracted and analysed in Excel', 'Bridge, NWC and net debt from the data-room TB', 'Question list generated from the gaps', 'Sharper FDD scope, lower advisor fees'],
    features: ['deal-document-analysis', 'ebitda-bridge', 'working-capital', 'find-adjustments'],
  },
  {
    slug: 'ca-firms',
    name: 'CA firms and accounting practices',
    title: 'FDD and Databook Automation for CA Firms | ZAF Tools',
    metaDescription: 'Add transaction advisory to your practice without adding headcount. ZAF Tools builds FDD databooks and QoE schedules from client trial balances in Excel.',
    h1: 'Transaction services without a transaction services team',
    intro: 'Accounting firms are asked for vendor due diligence, QoE for a sale, or a lender databook, and decline because the team is stretched. ZAF Tools makes the work viable at practice economics.',
    pains: ['Databook work is unprofitable at audit rates', 'No standard FDD templates', 'Partners review every number by hand', 'Clients expect a report, not a spreadsheet'],
    gains: ['Repeatable databook from any TB', 'FDD template and prompt libraries built in', 'Cross-checks and scorecards for review', 'Word report export in your house style'],
    features: ['trial-balance-mapping', 'build-financial-statements', 'model-audit', 'fdd-commentary'],
  },
];

export const templates = [
  {
    slug: 'ebitda-bridge-excel-template',
    name: 'EBITDA bridge Excel template',
    title: 'EBITDA Bridge in Excel: Template Layout and How to Build One',
    metaDescription: 'A practitioner guide to the EBITDA bridge Excel template with driver decomposition, waterfall chart and a cross-check to the P&L. Built by FDD practitioners.',
    h1: 'EBITDA bridge Excel template',
    what: 'A period-to-period EBITDA bridge with revenue, COGS and opex drivers, a waterfall chart built on native Excel charting, and a variance check against the P&L. Drop in two periods of P&L and the bridge and chart update.',
    includes: ['Bridge schedule for FY, YTD or LTM comparisons', 'Waterfall chart with positive and negative colouring', 'Cross-check row: bridge closing vs P&L EBITDA', 'Notes on how to present bridges in an FDD report'],
    keywords: ['EBITDA bridge template', 'EBITDA bridge Excel', 'waterfall chart template'],
  },
  {
    slug: 'quality-of-earnings-template',
    name: 'Quality of Earnings adjustments template',
    title: 'Quality of Earnings Template: Adjusted EBITDA Schedule Explained',
    metaDescription: 'The QoE template in Excel: reported-to-adjusted EBITDA schedule, adjustments log with categories and evidence, and run-rate view. From FDD practitioners.',
    h1: 'Quality of Earnings adjustments template',
    what: 'The schedule at the heart of every QoE report: reported EBITDA, management adjustments, diligence adjustments and adjusted EBITDA by period, driven by an adjustments log with category, evidence and status columns.',
    includes: ['Adjustments log with 12 standard categories', 'Reported-to-adjusted EBITDA by period', 'Run-rate and pro forma columns', 'Checklist of 40 common add-backs and deductions'],
    keywords: ['quality of earnings template', 'QoE template Excel', 'adjusted EBITDA schedule'],
  },
  {
    slug: 'financial-due-diligence-checklist',
    name: 'Financial due diligence checklist',
    title: 'Financial Due Diligence Checklist: 120+ Items for Buy-Side FDD',
    metaDescription: 'A practitioner’s FDD checklist covering information request, QoE, NWC, net debt, forecasts and reporting. 120+ items with owner and status.',
    h1: 'Financial due diligence checklist',
    what: 'The information request list and workplan used on a mid-market buy-side FDD, organised by area with owner, status and reference columns so it doubles as a tracker.',
    includes: ['Information request list by area', 'QoE, NWC, net debt and cash flow procedures', 'Forecast and business plan review steps', 'Reporting and SPA support items'],
    keywords: ['financial due diligence checklist', 'FDD checklist', 'due diligence information request list'],
  },
  {
    slug: 'management-questions-bank',
    name: 'Management questions bank for FDD',
    title: 'Management Questions for Financial Due Diligence (Question Bank)',
    metaDescription: 'A bank of management questions for financial due diligence, organised by revenue, costs, working capital, net debt, forecasts and systems. Built into ZAF Tools.',
    h1: 'Management questions bank',
    what: 'Questions asked on real engagements, grouped by area, with a column for the schedule that usually prompts them. Filter by area, copy into your MQ log.',
    includes: ['Revenue and margin questions', 'Cost base and headcount', 'Working capital and net debt', 'Forecast, systems and controls'],
    keywords: ['management questions due diligence', 'FDD questions list', 'due diligence questions for management'],
  },
  {
    slug: 'trial-balance-mapping-template',
    name: 'Trial balance mapping template',
    title: 'Trial Balance Mapping Template for FDD Databooks (Excel)',
    metaDescription: 'Excel template layout to map a client trial balance to an FDD reporting hierarchy: P&L, balance sheet, NWC and net debt codes, with unmapped-account checks.',
    h1: 'Trial balance mapping template',
    what: 'A three-sheet template: raw TB in, hierarchy codes, and a check sheet that flags unmapped accounts and confirms the mapped total equals the TB total.',
    includes: ['Standard FDD hierarchy (P&L, BS, NWC, ND, CF)', 'Mapping sheet with dropdown codes', 'Unmapped and total checks', 'Sign convention notes'],
    keywords: ['trial balance mapping template', 'chart of accounts mapping Excel', 'FDD hierarchy'],
  },
];

// Templates shipped in the add-in's Template Library. The add-in reads /public/templates/fdd_templates.json
// from the GitHub main branch — DO NOT move or rename that folder.
export const library = [
  { slug: 'ev-to-equity-bridge', name: 'EV to Equity Bridge', category: 'Valuation', kw: 'EV to equity bridge',
    desc: 'Reconciles headline enterprise value to the cash payable to the seller for the equity: net debt, debt-like items, the working capital adjustment against the peg, and locked-box leakage.',
    steps: ['Enterprise value (headline price)', 'Less: net financial debt', 'Less: debt-like items (deferred revenue, unpaid bonuses, tax liabilities)', 'Plus or minus: NWC against the peg', 'Equals: equity value payable to the seller'] },
  { slug: 'net-debt-schedule', name: 'Net Debt and Debt-like Items', category: 'Debt & NWC', kw: 'net debt and debt-like items',
    desc: 'Builds the net debt figure that flows into the EV-to-equity bridge: cash, borrowings, leases and the debt-like items buyers and sellers argue about.',
    steps: ['Cash, and cash that is trapped or restricted', 'Bank and shareholder borrowings', 'Lease liabilities (IFRS 16 / ASC 842)', 'Debt-like items, each with a rationale', 'Reported versus adjusted net debt'] },
  { slug: 'ebitda-normalisation', name: 'EBITDA Normalisation Bridge (QoE)', category: 'Quality of Earnings', kw: 'EBITDA normalisation',
    desc: 'Reported EBITDA adjusted to a maintainable, run-rate basis for pricing, with each adjustment categorised and evidenced.',
    steps: ['Reported EBITDA by period', 'Management adjustments', 'Diligence adjustments: one-offs, owner costs, related-party items', 'Pro forma and run-rate adjustments', 'Adjusted EBITDA and margin'] },
  { slug: 'price-volume-mix-analysis', name: 'Price-Volume-Mix Analysis', category: 'Revenue Analysis', kw: 'price volume mix analysis',
    desc: 'Decomposes the revenue variance between two periods into price, volume, mix and interaction effects, by product.',
    steps: ['Units and revenue by product for two periods', 'Price effect', 'Volume effect', 'Mix and interaction effects', 'Revenue bridge chart'] },
  { slug: 'price-volume-mix-3-year', name: 'Price-Volume-Mix Analysis (3-Year Trend)', category: 'Revenue Analysis', kw: '3 year price volume mix analysis',
    desc: 'Price, volume, mix and interaction effects across three consecutive periods, with a chained three-period revenue bridge.',
    steps: ['Three periods of units and revenue by product', 'Year-on-year PVM for each pair of periods', 'Chained three-period revenue bridge', 'Product-level drivers of growth'] },
  { slug: 'ar-ageing-schedule', name: 'AR Ageing Schedule', category: 'Balance Sheet', kw: 'accounts receivable ageing schedule',
    desc: 'Accounts receivable ageing with Not due, 0-30, 31-60, 61-90 and over 90 day buckets. Paste customer invoices and the ageing, bucket split and totals calculate automatically.',
    steps: ['Paste open customer invoices', 'Days overdue computed from the due date', 'Bucket split and totals', 'Provisioning discussion for balances over 90 days'] },
  { slug: 'ap-ageing-schedule', name: 'AP Ageing Schedule', category: 'Balance Sheet', kw: 'accounts payable ageing schedule',
    desc: 'Accounts payable ageing with Not due, 0-30, 31-60, 61-90 and over 90 day buckets. Paste vendor invoices and the ageing, bucket split and totals calculate automatically.',
    steps: ['Paste open vendor invoices', 'Days overdue computed from the due date', 'Bucket split and totals', 'Stretched-payables check before setting the NWC peg'] },
];

// Hours saved per engagement. ILLUSTRATIVE estimates — TODO(Abhishek): replace with measured numbers.
export const hoursSaved = [
  { task: 'Trial balance import, translation and mapping', manual: 10, zaf: 1 },
  { task: 'Build P&L, balance sheet, cash flow and schedules', manual: 14, zaf: 2 },
  { task: 'Quality of Earnings: find and schedule adjustments', manual: 12, zaf: 3 },
  { task: 'EBITDA bridge and working capital analysis', manual: 8, zaf: 1.5 },
  { task: 'FDD commentary on P&L, balance sheet, cash flow and NWC', manual: 12, zaf: 2 },
  { task: 'Management questions list', manual: 4, zaf: 0.5 },
  { task: 'PDF and scanned statements into Excel', manual: 5, zaf: 0.5 },
  { task: 'Export to Word and PowerPoint, cover page and index', manual: 6, zaf: 0.5 },
];

// Customer quotes. Keep show=false until each client has approved the exact wording and name.
export const testimonials = {
  show: false,
  items: [
    { quote: '', who: '', firm: 'Windy Street' },
    { quote: '', who: '', firm: 'BPS Analytics' },
  ],
};
