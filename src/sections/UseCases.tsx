import { useEffect, useRef } from 'react';
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { 
  TrendingUp, Building2, Calculator, Briefcase, 
  Users, ArrowRight
} from 'lucide-react';

gsap.registerPlugin(ScrollTrigger);

const UseCases = () => {
  const sectionRef = useRef<HTMLElement>(null);
  const cardsRef = useRef<HTMLDivElement>(null);

  const roles = [
    {
      icon: TrendingUp,
      title: 'Investment Banking',
      description: 'Build pitch-ready models faster. Automated formatting, error detection, and one-click sensitivity analysis.',
      features: ['Pitchbook formatting', 'LBO model audit', 'Comps automation'],
      color: 'from-blue-500/20 to-blue-600/10',
    },
    {
      icon: Building2,
      title: 'Private Equity',
      description: 'Due diligence made thorough. Catch every hardcode, verify every assumption, and build defensible models.',
      features: ['DD model review', 'IC-ready outputs', 'Portfolio tracking'],
      color: 'from-emerald-500/20 to-emerald-600/10',
    },
    {
      icon: Calculator,
      title: 'CA & Audit Firms',
      description: 'Review client workbooks with confidence. Standardized checks ensure nothing slips through.',
      features: ['Standardized audit', 'Error tracing', 'Compliance checks'],
      color: 'from-amber-500/20 to-amber-600/10',
    },
    {
      icon: Briefcase,
      title: 'Corporate Finance',
      description: 'Monthly close, budgeting, and forecasting—streamlined with intelligent automation.',
      features: ['FP&A automation', 'Variance analysis', 'Board reporting'],
      color: 'from-purple-500/20 to-purple-600/10',
    },
    {
      icon: Users,
      title: 'Consulting',
      description: 'Deliver client-ready analysis faster. Professional outputs that match your firm\'s standards.',
      features: ['Client formatting', 'Model templates', 'Quality control'],
      color: 'from-rose-500/20 to-rose-600/10',
    },
  ];

  useEffect(() => {
    const ctx = gsap.context(() => {
      // Header animation
      gsap.fromTo(
        '.usecases-header',
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

      // Cards stagger animation
      const cards = cardsRef.current?.querySelectorAll('.role-card');
      if (cards) {
        gsap.fromTo(
          cards,
          { y: 50, opacity: 0 },
          {
            y: 0,
            opacity: 1,
            duration: 0.5,
            stagger: 0.1,
            scrollTrigger: {
              trigger: cardsRef.current,
              start: 'top 75%',
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
      className="relative py-24 lg:py-32 overflow-hidden"
    >
      {/* Background */}
      <div className="absolute inset-0 bg-zaf-navy-darker" />
      
      {/* Subtle pattern */}
      <div 
        className="absolute inset-0 opacity-[0.02]"
        style={{
          backgroundImage: `radial-gradient(circle at 1px 1px, rgba(201, 168, 76, 0.8) 1px, transparent 0)`,
          backgroundSize: '40px 40px',
        }}
      />

      <div className="relative z-10 w-full section-padding">
        <div className="max-w-7xl mx-auto">
          {/* Section Header */}
          <div className="usecases-header text-center mb-16">
            <span className="label-mono mb-4 block">USE CASES</span>
            <h2 className="heading-lg text-zaf-text mb-4">
              Built For{' '}
              <span className="text-gradient-gold">Every Finance Role</span>
            </h2>
            <p className="body-md max-w-2xl mx-auto">
              From investment banking to corporate FP&A, ZAF Tools adapts to your workflow and elevates your output.
            </p>
          </div>

          {/* Roles Grid */}
          <div 
            ref={cardsRef}
            className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6"
          >
            {roles.map((role, index) => (
              <div
                key={index}
                className="role-card group relative overflow-hidden"
              >
                {/* Gradient background */}
                <div className={`absolute inset-0 bg-gradient-to-br ${role.color} opacity-0 group-hover:opacity-100 transition-opacity duration-500`} />
                
                {/* Content */}
                <div className="relative z-10">
                  {/* Icon */}
                  <div className="w-12 h-12 rounded-xl bg-zaf-navy/50 flex items-center justify-center mb-5 group-hover:bg-zaf-gold/10 group-hover:border-zaf-gold/30 border border-transparent transition-all duration-300">
                    <role.icon className="w-6 h-6 text-zaf-gold" />
                  </div>

                  {/* Title */}
                  <h3 className="text-xl font-semibold text-zaf-text mb-3">
                    {role.title}
                  </h3>

                  {/* Description */}
                  <p className="text-sm text-zaf-text-muted mb-5 leading-relaxed">
                    {role.description}
                  </p>

                  {/* Features */}
                  <div className="flex flex-wrap gap-2 mb-5">
                    {role.features.map((feature, fIndex) => (
                      <span 
                        key={fIndex}
                        className="px-3 py-1 text-xs font-medium rounded-full bg-white/[0.05] text-zaf-text-muted border border-white/5"
                      >
                        {feature}
                      </span>
                    ))}
                  </div>

                  {/* CTA */}
                  <button className="flex items-center gap-2 text-sm font-medium text-zaf-gold opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                    Learn more
                    <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                  </button>
                </div>

                {/* Border glow on hover */}
                <div className="absolute inset-0 rounded-2xl border border-transparent group-hover:border-zaf-gold/20 transition-colors duration-300 pointer-events-none" />
              </div>
            ))}
          </div>

          {/* Bottom CTA */}
          <div className="mt-16 text-center">
            <p className="text-zaf-text-muted mb-4">
              Not sure if ZAF Tools fits your workflow?
            </p>
            <a href="mailto:abhishek.bhandari@zaftool.com" className="btn-outline inline-flex items-center gap-2">
              Schedule a demo
              <ArrowRight className="w-4 h-4" />
            </a>
          </div>
        </div>
      </div>
    </section>
  );
};

export default UseCases;
