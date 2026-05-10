import { useEffect, useRef } from 'react';
import { Helmet } from 'react-helmet-async';
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { Download, ChevronRight, Rocket, Zap, Clock } from 'lucide-react';
import Navigation from '../sections/Navigation';
import Footer from '../sections/Footer';

gsap.registerPlugin(ScrollTrigger);

const changelogData = [
  {
    version: 'v4.1',
    date: 'May 2026',
    headline: 'Payments, licensing & installer — fully automated',
    features: [
      'Razorpay subscription payments with automatic licence key delivery via email',
      'New pricing tiers: Solo ($19/mo), Team ($49/mo), Firm ($129/mo)',
      'MSI Windows installer — one-click install, no manual setup',
      'Enter Licence Key button added to ribbon',
      'Silent auto-update check on Excel open',
      'Version audit log — tracks AI usage across sheets'
    ]
  },
  {
    version: 'v4.0',
    date: 'April 2026',
    headline: 'AI engine rebuilt with multi-provider support',
    features: [
      'ZAF AI module launched — BYOK (Bring Your Own Key) model',
      '7 AI providers: OpenAI, Anthropic, Google Gemini, Kimi, MiniMax, OpenRouter, DeepSeek',
      'FDD Commentary — AI generates Big 4-style commentary for P&L, BS, NWC, CF, ND tabs',
      'Prompt Library — one-click FDD/M&A prompts built in',
      'Export to Word — push AI analysis into formatted .docx instantly',
      'JSON Model Registry — new AI models added without rebuilding the add-in',
      'Analysis History — full log of all AI runs with re-run capability'
    ]
  },
  {
    version: 'v3.0',
    date: 'January 2026',
    headline: '30+ productivity tools for FDD professionals',
    features: [
      'ZAF Classic module — complete suite of Excel productivity tools',
      'Model Audit — full formula and hardcode checker across workbook',
      'Consolidate Sheets / Files — merge data in one click',
      'Cover Page, Index Sheet — professional document formatting',
      'Anomaly Detection — statistical outlier flagging',
      'Trace Precedents / Dependents — visual formula mapping',
      'Text cleaning, date fixing, text-to-number conversion'
    ]
  }
];

const upcomingFeatures = [
  { title: 'PDF & Image Ingestion', description: 'Drop a PDF of financials, AI extracts data into Excel' },
  { title: 'Run Full FDD', description: 'One button chains all FDD sheets and exports Word report' },
  { title: 'Trial Balance → Financial Statements', description: 'Map accounts, AI builds all 4 statements' }
];

const Changelog = () => {
  const mainRef = useRef<HTMLDivElement>(null);
  const timelineRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const ctx = gsap.context(() => {
      // Hero section animation
      gsap.from('.changelog-hero > *', {
        y: 30,
        opacity: 0,
        duration: 0.8,
        stagger: 0.2,
        ease: 'power3.out'
      });

      // Timeline items animation
      const items = gsap.utils.toArray('.timeline-item');
      items.forEach((item: any) => {
        gsap.from(item, {
          y: 50,
          opacity: 0,
          duration: 0.8,
          scrollTrigger: {
            trigger: item,
            start: 'top 85%',
            toggleActions: 'play none none reverse'
          }
        });
      });

      // Coming soon cards animation
      gsap.from('.coming-soon-card', {
        scale: 0.95,
        opacity: 0,
        duration: 0.6,
        stagger: 0.15,
        scrollTrigger: {
          trigger: '.coming-soon-section',
          start: 'top 80%'
        }
      });
    }, mainRef);

    return () => ctx.revert();
  }, []);

  return (
    <div ref={mainRef} className="min-h-screen bg-zaf-navy-darker text-zaf-text selection:bg-zaf-gold/30">
      <Helmet>
        <title>ZAF Tools Changelog — Version History & Release Notes</title>
        <meta name="description" content="See every feature shipped in ZAF Tools. Version history, release notes and what's coming next for the leading FDD Excel add-in." />
      </Helmet>

      <div className="grain-overlay" />
      <Navigation />

      <main className="relative pt-32 pb-20">
        {/* Hero Section */}
        <div className="section-padding mb-20">
          <div className="max-w-4xl mx-auto text-center changelog-hero">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-zaf-gold/10 border border-zaf-gold/20 text-zaf-gold text-xs font-medium mb-6">
              <Rocket className="w-3.5 h-3.5" />
              <span>Product Updates</span>
            </div>
            <h1 className="text-4xl md:text-6xl font-bold mb-6 tracking-tight">
              What's <span className="text-zaf-gold">New</span>
            </h1>
            <p className="text-lg text-zaf-text-muted max-w-2xl mx-auto leading-relaxed">
              We're constantly shipping updates to make ZAF Tools the most powerful 
              Excel companion for finance professionals.
            </p>
          </div>
        </div>

        {/* Timeline Section */}
        <div className="section-padding relative" ref={timelineRef}>
          <div className="max-w-4xl mx-auto">
            {/* Vertical Line */}
            <div className="absolute left-1/2 -translate-x-1/2 top-0 bottom-0 w-px bg-gradient-to-b from-zaf-gold/50 via-zaf-gold/20 to-transparent hidden md:block" />

            <div className="space-y-24 relative">
              {changelogData.map((item, index) => (
                <div key={item.version} className="timeline-item relative grid md:grid-cols-2 gap-8 md:gap-16">
                  {/* Date/Version for Desktop (Left) */}
                  <div className={`hidden md:flex flex-col justify-center ${index % 2 === 0 ? 'text-right items-end' : 'order-last text-left items-start'}`}>
                    <div className="inline-block px-4 py-1 rounded-full bg-zaf-gold text-zaf-navy-darker font-bold text-sm mb-3">
                      {item.version}
                    </div>
                    <div className="flex items-center gap-2 text-zaf-text-muted font-medium">
                      <Clock className="w-4 h-4" />
                      {item.date}
                    </div>
                  </div>

                  {/* Content Card (Right/Left depending on index) */}
                  <div className={`bg-white/[0.03] border border-white/10 rounded-2xl p-8 backdrop-blur-sm hover:border-zaf-gold/30 transition-colors duration-500 relative group`}>
                    {/* Mobile Version/Date Header */}
                    <div className="flex md:hidden items-center justify-between mb-6">
                      <span className="px-3 py-1 rounded-full bg-zaf-gold text-zaf-navy-darker font-bold text-xs">
                        {item.version}
                      </span>
                      <span className="text-zaf-text-muted text-sm font-medium">{item.date}</span>
                    </div>

                    {/* Connector Dot */}
                    <div className={`absolute top-1/2 -translate-y-1/2 w-4 h-4 rounded-full bg-zaf-gold shadow-[0_0_15px_rgba(201,168,76,0.5)] border-4 border-zaf-navy-darker hidden md:block
                      ${index % 2 === 0 ? '-left-[41px]' : '-right-[41px]'}`} 
                    />

                    <h3 className="text-xl font-bold text-zaf-text mb-4 group-hover:text-zaf-gold transition-colors">
                      {item.headline}
                    </h3>
                    
                    <ul className="space-y-3 mb-8">
                      {item.features.map((feature, i) => (
                        <li key={i} className="flex items-start gap-3 text-zaf-text-muted text-sm leading-relaxed">
                          <ChevronRight className="w-4 h-4 mt-0.5 text-zaf-gold flex-shrink-0" />
                          <span>{feature}</span>
                        </li>
                      ))}
                    </ul>

                    <a 
                      href="/download" 
                      className="inline-flex items-center gap-2 text-sm font-semibold text-zaf-gold hover:text-white transition-colors group/btn"
                    >
                      <Download className="w-4 h-4" />
                      Download Update
                      <ChevronRight className="w-4 h-4 group-hover/btn:translate-x-1 transition-transform" />
                    </a>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Coming Soon Section */}
        <div className="section-padding mt-32 coming-soon-section">
          <div className="max-w-4xl mx-auto">
            <div className="text-center mb-12">
              <h2 className="text-3xl font-bold mb-4">Coming soon — <span className="text-zaf-gold">v4.2</span></h2>
              <p className="text-zaf-text-muted">What we're currently building for the next major release.</p>
            </div>
            
            <div className="grid sm:grid-cols-3 gap-6">
              {upcomingFeatures.map((feature) => (
                <div key={feature.title} className="coming-soon-card bg-white/[0.02] border border-white/5 rounded-xl p-6 hover:bg-white/[0.04] transition-all duration-300">
                  <div className="w-10 h-10 rounded-lg bg-zaf-gold/10 flex items-center justify-center text-zaf-gold mb-4">
                    <Zap className="w-5 h-5" />
                  </div>
                  <h4 className="font-bold text-sm mb-2">{feature.title}</h4>
                  <p className="text-xs text-zaf-text-muted leading-relaxed">{feature.description}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </main>

      <Footer />
    </div>
  );
};

export default Changelog;
