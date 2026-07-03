import { useEffect, useRef } from 'react';
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { 
  Paintbrush, Navigation, Database, Sparkles, 
  Search, Zap, Bot, Lightbulb, MessageSquare, 
  BarChart3, Code2, AlertOctagon
} from 'lucide-react';

gsap.registerPlugin(ScrollTrigger);

const Solution = () => {
  const sectionRef = useRef<HTMLElement>(null);
  const coreRef = useRef<HTMLDivElement>(null);
  const aiRef = useRef<HTMLDivElement>(null);

  const coreTools = [
    { icon: Paintbrush, label: 'Formatting', desc: 'One-click professional styling' },
    { icon: Navigation, label: 'Navigation', desc: 'Jump anywhere in seconds' },
    { icon: Database, label: 'Data', desc: 'Smart selection & manipulation' },
    { icon: Search, label: 'Cleaning', desc: 'Remove errors & duplicates' },
    { icon: AlertOctagon, label: 'Model Audit', desc: '6-check verification engine' },
    { icon: Zap, label: 'Productivity', desc: 'Shortcuts & automation' },
  ];

  const aiFeatures = [
    { icon: Bot, label: 'AI Model Builder', desc: 'Generate complete financial models' },
    { icon: Lightbulb, label: 'Formula Explainer', desc: 'Understand any formula instantly' },
    { icon: MessageSquare, label: 'Ask Zaffy', desc: 'Chat with your spreadsheet' },
    { icon: BarChart3, label: 'Financial Analysis', desc: 'AI-powered insights' },
    { icon: Code2, label: 'Formula Writer', desc: 'Natural language to Excel' },
    { icon: AlertOctagon, label: 'Anomaly Detection', desc: 'Spot errors before they matter' },
  ];

  useEffect(() => {
    const ctx = gsap.context(() => {
      // Header animation
      gsap.fromTo(
        '.solution-header',
        { y: 40, opacity: 0 },
        {
          y: 0,
          opacity: 1,
          duration: 0.6,
          scrollTrigger: {
            trigger: sectionRef.current,
            start: 'top 80%',
            toggleActions: 'play none none reverse',
          },
        }
      );

      // Core section animation
      gsap.fromTo(
        coreRef.current,
        { x: -60, opacity: 0 },
        {
          x: 0,
          opacity: 1,
          duration: 0.7,
          scrollTrigger: {
            trigger: coreRef.current,
            start: 'top 75%',
            toggleActions: 'play none none reverse',
          },
        }
      );

      // AI section animation
      gsap.fromTo(
        aiRef.current,
        { x: 60, opacity: 0 },
        {
          x: 0,
          opacity: 1,
          duration: 0.7,
          scrollTrigger: {
            trigger: aiRef.current,
            start: 'top 75%',
            toggleActions: 'play none none reverse',
          },
        }
      );

      // Tool cards stagger
      const toolCards = sectionRef.current?.querySelectorAll('.tool-card');
      if (toolCards) {
        gsap.fromTo(
          toolCards,
          { y: 30, opacity: 0 },
          {
            y: 0,
            opacity: 1,
            duration: 0.4,
            stagger: 0.05,
            scrollTrigger: {
              trigger: toolCards[0],
              start: 'top 80%',
              toggleActions: 'play none none reverse',
            },
          }
        );
      }
    }, sectionRef);

    return () => ctx.revert();
  }, []);

  return (
    <section
      ref={sectionRef}
      id="solutions"
      className="relative py-24 lg:py-32 overflow-hidden"
    >
      {/* Background */}
      <div className="absolute inset-0 bg-zaf-navy-darker" />
      
      {/* Subtle radial gradient */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-zaf-navy/30 rounded-full blur-3xl opacity-50" />

      <div className="relative z-10 w-full section-padding">
        <div className="max-w-7xl mx-auto">
          {/* Section Header */}
          <div className="solution-header text-center mb-16">
            <span className="label-mono mb-4 block">THE SOLUTION</span>
            <h2 className="heading-lg text-zaf-text mb-4">
              Two Components.{' '}
              <span className="text-gradient-gold">One Powerful Suite.</span>
            </h2>
            <p className="body-md max-w-2xl mx-auto">
              ZAF Core handles the fundamentals. ZAF AI brings intelligence. Together, they transform how you work in Excel.
            </p>
          </div>

          {/* Two Component Cards */}
          <div className="grid lg:grid-cols-2 gap-8">
            {/* ZAF Core */}
            <div 
              ref={coreRef}
              className="gradient-border p-1"
            >
              <div className="h-full bg-zaf-navy-dark/60 rounded-2xl p-8">
                {/* Header */}
                <div className="flex items-center gap-4 mb-8">
                  <div className="w-14 h-14 rounded-xl bg-zaf-navy flex items-center justify-center border border-zaf-gold/30">
                    <Sparkles className="w-7 h-7 text-zaf-gold" />
                  </div>
                  <div>
                    <h3 className="text-2xl font-bold text-zaf-text">ZAF Core</h3>
                    <p className="text-sm text-zaf-text-muted">30+ Professional Tools</p>
                  </div>
                </div>

                {/* Tools Grid */}
                <div className="grid sm:grid-cols-2 gap-4">
                  {coreTools.map((tool, index) => (
                    <div 
                      key={index}
                      className="tool-card p-4 rounded-xl bg-white/[0.03] border border-white/5 hover:border-zaf-gold/30 hover:bg-white/[0.05] transition-all duration-300 group"
                    >
                      <div className="flex items-start gap-3">
                        <div className="w-9 h-9 rounded-lg bg-zaf-navy/50 flex items-center justify-center flex-shrink-0 group-hover:bg-zaf-gold/10 transition-colors">
                          <tool.icon className="w-4 h-4 text-zaf-gold" />
                        </div>
                        <div>
                          <h4 className="text-sm font-semibold text-zaf-text mb-0.5">{tool.label}</h4>
                          <p className="text-xs text-zaf-text-muted">{tool.desc}</p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>

                {/* Flagship badge */}
                <div className="mt-6 p-4 rounded-xl bg-zaf-gold/10 border border-zaf-gold/30">
                  <div className="flex items-center gap-2 mb-1">
                    <Sparkles className="w-4 h-4 text-zaf-gold" />
                    <span className="text-xs font-semibold text-zaf-gold uppercase tracking-wider">Flagship</span>
                  </div>
                  <p className="text-sm text-zaf-text">Model Audit Engine — 6-check verification system</p>
                </div>
              </div>
            </div>

            {/* ZAF AI */}
            <div 
              ref={aiRef}
              className="gradient-border p-1"
            >
              <div className="h-full bg-zaf-navy-dark/60 rounded-2xl p-8">
                {/* Header */}
                <div className="flex items-center gap-4 mb-8">
                  <div className="w-14 h-14 rounded-xl bg-gradient-to-br from-zaf-gold/30 to-zaf-gold/10 flex items-center justify-center border border-zaf-gold/40">
                    <Bot className="w-7 h-7 text-zaf-gold" />
                  </div>
                  <div>
                    <h3 className="text-2xl font-bold text-zaf-text">ZAF AI</h3>
                    <p className="text-sm text-zaf-text-muted">Intelligence Layer</p>
                  </div>
                </div>

                {/* Features Grid */}
                <div className="grid sm:grid-cols-2 gap-4">
                  {aiFeatures.map((feature, index) => (
                    <div 
                      key={index}
                      className="tool-card p-4 rounded-xl bg-white/[0.03] border border-white/5 hover:border-zaf-gold/30 hover:bg-white/[0.05] transition-all duration-300 group"
                    >
                      <div className="flex items-start gap-3">
                        <div className="w-9 h-9 rounded-lg bg-zaf-gold/10 flex items-center justify-center flex-shrink-0 group-hover:bg-zaf-gold/20 transition-colors">
                          <feature.icon className="w-4 h-4 text-zaf-gold" />
                        </div>
                        <div>
                          <h4 className="text-sm font-semibold text-zaf-text mb-0.5">{feature.label}</h4>
                          <p className="text-xs text-zaf-text-muted">{feature.desc}</p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>

                {/* New feature badge */}
                <div className="mt-6 p-4 rounded-xl bg-zaf-navy/50 border border-white/10">
                  <div className="flex items-center gap-2 mb-1">
                    <div className="px-2 py-0.5 rounded bg-zaf-gold text-zaf-navy-darker text-[10px] font-bold">NEW</div>
                    <span className="text-xs font-semibold text-zaf-text uppercase tracking-wider">AI Model Builder</span>
                  </div>
                  <p className="text-sm text-zaf-text-muted">Generate complete 3-statement models from scratch</p>
                </div>
              </div>
            </div>
          </div>

          {/* Integration note */}
          <div className="mt-12 text-center">
            <div className="inline-flex items-center gap-3 px-6 py-3 rounded-full bg-white/[0.03] border border-white/10">
              <div className="flex -space-x-2">
                <div className="w-8 h-8 rounded-full bg-zaf-navy border-2 border-zaf-navy-darker flex items-center justify-center">
                  <Sparkles className="w-4 h-4 text-zaf-gold" />
                </div>
                <div className="w-8 h-8 rounded-full bg-zaf-gold/20 border-2 border-zaf-navy-darker flex items-center justify-center">
                  <Bot className="w-4 h-4 text-zaf-gold" />
                </div>
              </div>
              <span className="text-sm text-zaf-text-muted">
                Seamlessly integrated. Works together as one.
              </span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default Solution;
