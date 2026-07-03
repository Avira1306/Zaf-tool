import { useEffect, useRef } from 'react';
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { CheckCircle2, XCircle, AlertCircle, Quote } from 'lucide-react';

gsap.registerPlugin(ScrollTrigger);

const FlagshipFeature = () => {
  const sectionRef = useRef<HTMLElement>(null);
  const checksRef = useRef<HTMLDivElement>(null);

  const auditChecks = [
    { 
      name: 'Formula Consistency', 
      status: 'pass',
      desc: 'All formulas consistent across sheets'
    },
    { 
      name: 'Hardcode Detection', 
      status: 'pass',
      desc: 'No hardcoded values in calculation cells'
    },
    { 
      name: 'Circular Reference', 
      status: 'pass',
      desc: 'No circular references found'
    },
    { 
      name: 'Link Integrity', 
      status: 'warning',
      desc: '2 external links need verification'
    },
    { 
      name: 'Naming Convention', 
      status: 'pass',
      desc: 'All cells follow naming standards'
    },
    { 
      name: 'Balance Check', 
      status: 'pass',
      desc: 'Balance sheet balances correctly'
    },
  ];

  const scoreColor = (status: string) => {
    switch (status) {
      case 'pass': return 'text-emerald-400';
      case 'warning': return 'text-amber-400';
      case 'fail': return 'text-rose-400';
      default: return 'text-zaf-text-muted';
    }
  };

  const scoreBg = (status: string) => {
    switch (status) {
      case 'pass': return 'bg-emerald-400/10';
      case 'warning': return 'bg-amber-400/10';
      case 'fail': return 'bg-rose-400/10';
      default: return 'bg-white/5';
    }
  };

  const scoreIcon = (status: string) => {
    switch (status) {
      case 'pass': return CheckCircle2;
      case 'warning': return AlertCircle;
      case 'fail': return XCircle;
      default: return CheckCircle2;
    }
  };

  useEffect(() => {
    const ctx = gsap.context(() => {
      // Header animation
      gsap.fromTo(
        '.flagship-header',
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

      // Scorecard animation
      gsap.fromTo(
        '.scorecard',
        { scale: 0.95, opacity: 0 },
        {
          scale: 1,
          opacity: 1,
          duration: 0.7,
          scrollTrigger: {
            trigger: '.scorecard',
            start: 'top 75%',
            toggleActions: 'play none none reverse',
          },
        }
      );

      // Check items stagger
      const checks = checksRef.current?.querySelectorAll('.check-item');
      if (checks) {
        gsap.fromTo(
          checks,
          { x: -20, opacity: 0 },
          {
            x: 0,
            opacity: 1,
            duration: 0.4,
            stagger: 0.08,
            scrollTrigger: {
              trigger: checksRef.current,
              start: 'top 80%',
              toggleActions: 'play none none reverse',
            },
          }
        );
      }

      // Testimonial animation
      gsap.fromTo(
        '.testimonial-card',
        { y: 30, opacity: 0 },
        {
          y: 0,
          opacity: 1,
          duration: 0.6,
          scrollTrigger: {
            trigger: '.testimonial-card',
            start: 'top 85%',
            toggleActions: 'play none none reverse',
          },
        }
      );
    }, sectionRef);

    return () => ctx.revert();
  }, []);

  return (
    <section
      ref={sectionRef}
      className="relative py-24 lg:py-32 overflow-hidden"
    >
      {/* Background */}
      <div className="absolute inset-0 bg-zaf-navy-darker" />
      
      {/* Accent gradient */}
      <div className="absolute top-0 right-0 w-1/2 h-full bg-gradient-to-l from-zaf-navy/20 to-transparent" />

      <div className="relative z-10 w-full section-padding">
        <div className="max-w-7xl mx-auto">
          {/* Section Header */}
          <div className="flagship-header text-center mb-16">
            <span className="label-mono mb-4 block">FLAGSHIP FEATURE</span>
            <h2 className="heading-lg text-zaf-text mb-4">
              Model Audit{' '}
              <span className="text-gradient-gold">Engine</span>
            </h2>
            <p className="body-md max-w-2xl mx-auto">
              Six automated checks that catch errors before they become expensive mistakes. 
              Color-coded scorecard shows exactly what needs attention.
            </p>
          </div>

          {/* Main Content Grid */}
          <div className="grid lg:grid-cols-5 gap-8">
            {/* Scorecard - Takes 3 columns */}
            <div className="lg:col-span-3">
              <div className="scorecard gradient-border p-1">
                <div className="bg-zaf-navy-dark/80 rounded-2xl p-6 sm:p-8">
                  {/* Scorecard Header */}
                  <div className="flex items-center justify-between mb-6">
                    <div>
                      <h3 className="text-lg font-semibold text-zaf-text">Audit Scorecard</h3>
                      <p className="text-sm text-zaf-text-muted">Workbook: Q4_Financial_Model_v3.xlsx</p>
                    </div>
                    <div className="flex items-center gap-3">
                      <div className="text-right">
                        <div className="text-3xl font-bold text-emerald-400">94</div>
                        <div className="text-xs text-zaf-text-muted">/100</div>
                      </div>
                      <div className="w-14 h-14 rounded-full bg-emerald-400/10 border-2 border-emerald-400 flex items-center justify-center">
                        <CheckCircle2 className="w-7 h-7 text-emerald-400" />
                      </div>
                    </div>
                  </div>

                  {/* Progress bar */}
                  <div className="h-2 bg-white/10 rounded-full overflow-hidden mb-8">
                    <div className="h-full w-[94%] bg-gradient-to-r from-emerald-400 via-emerald-400 to-amber-400 rounded-full" />
                  </div>

                  {/* Checks List */}
                  <div ref={checksRef} className="space-y-3">
                    {auditChecks.map((check, index) => {
                      const Icon = scoreIcon(check.status);
                      return (
                        <div 
                          key={index}
                          className="check-item flex items-center justify-between p-4 rounded-xl bg-white/[0.03] hover:bg-white/[0.05] transition-colors"
                        >
                          <div className="flex items-center gap-4">
                            <div className={`w-10 h-10 rounded-lg ${scoreBg(check.status)} flex items-center justify-center`}>
                              <Icon className={`w-5 h-5 ${scoreColor(check.status)}`} />
                            </div>
                            <div>
                              <p className="text-sm font-medium text-zaf-text">{check.name}</p>
                              <p className="text-xs text-zaf-text-muted">{check.desc}</p>
                            </div>
                          </div>
                          <div className={`text-xs font-semibold uppercase ${scoreColor(check.status)}`}>
                            {check.status}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            </div>

            {/* Right Column - Testimonial + Stats */}
            <div className="lg:col-span-2 space-y-6">
              {/* Testimonial */}
              <div className="testimonial-card feature-card">
                <Quote className="w-8 h-8 text-zaf-gold/40 mb-4" />
                <p className="text-zaf-text mb-6 leading-relaxed">
                  &ldquo;The Model Audit Engine caught a $2M error in our acquisition model that would have been catastrophic. 
                  It&apos;s now mandatory for every deal we review.&rdquo;
                </p>
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-full bg-zaf-navy flex items-center justify-center text-sm font-semibold text-zaf-gold">
                    SK
                  </div>
                  <div>
                    <p className="text-sm font-medium text-zaf-text">Senior Analyst</p>
                    <p className="text-xs text-zaf-text-muted">ICRA Ratings</p>
                  </div>
                </div>
              </div>

              {/* Stats */}
              <div className="grid grid-cols-2 gap-4">
                <div className="feature-card text-center">
                  <div className="text-3xl font-bold text-zaf-gold mb-1">6</div>
                  <div className="text-xs text-zaf-text-muted">Automated Checks</div>
                </div>
                <div className="feature-card text-center">
                  <div className="text-3xl font-bold text-zaf-gold mb-1">&lt;3s</div>
                  <div className="text-xs text-zaf-text-muted">Scan Time</div>
                </div>
                <div className="feature-card text-center">
                  <div className="text-3xl font-bold text-zaf-gold mb-1">98%</div>
                  <div className="text-xs text-zaf-text-muted">Error Detection</div>
                </div>
                <div className="feature-card text-center">
                  <div className="text-3xl font-bold text-zaf-gold mb-1">0</div>
                  <div className="text-xs text-zaf-text-muted">False Positives</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default FlagshipFeature;
