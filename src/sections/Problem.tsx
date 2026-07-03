import { useEffect, useRef } from 'react';
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { FileX, AlertTriangle, FolderKanban, PenTool } from 'lucide-react';

gsap.registerPlugin(ScrollTrigger);

const Problem = () => {
  const sectionRef = useRef<HTMLElement>(null);
  const cardsRef = useRef<HTMLDivElement>(null);

  const painPoints = [
    {
      icon: FileX,
      title: 'Formatting Hell',
      description: 'Hours wasted on manual formatting, inconsistent styles, and repetitive cell adjustments across multiple sheets.',
      solution: 'One-click professional formatting',
    },
    {
      icon: AlertTriangle,
      title: 'Hidden Errors',
      description: 'Hardcoded values, broken formulas, and inconsistent references lurking in your models, waiting to cause disaster.',
      solution: '6-check audit engine + AI explanations',
    },
    {
      icon: FolderKanban,
      title: 'Manual Consolidation',
      description: 'Copy-pasting data from multiple files, manually mapping columns, and reconciling differences takes days.',
      solution: 'Auto-merge files + AI mapping',
    },
    {
      icon: PenTool,
      title: 'Building From Scratch',
      description: 'Starting every model from zero, rewriting the same formulas, and recreating templates wastes precious time.',
      solution: 'NEW: AI generates complete models',
    },
  ];

  useEffect(() => {
    const ctx = gsap.context(() => {
      // Title animation
      gsap.fromTo(
        '.problem-title',
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
      const cards = cardsRef.current?.querySelectorAll('.problem-card');
      if (cards) {
        gsap.fromTo(
          cards,
          { y: 60, opacity: 0 },
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
      id="features"
      className="relative py-24 lg:py-32 overflow-hidden"
    >
      {/* Background */}
      <div className="absolute inset-0 bg-zaf-navy-darker" />
      
      {/* Accent line */}
      <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-zaf-gold/30 to-transparent" />

      <div className="relative z-10 w-full section-padding">
        <div className="max-w-7xl mx-auto">
          {/* Section Header */}
          <div className="problem-title text-center mb-16">
            <span className="label-mono mb-4 block">THE PROBLEM</span>
            <h2 className="heading-lg text-zaf-text mb-4">
              Excel Work Shouldn&apos;t Be This{' '}
              <span className="text-gradient-gold">Hard</span>
            </h2>
            <p className="body-md max-w-2xl mx-auto">
              Finance professionals waste 40% of their time on repetitive tasks that should be automated. Here&apos;s what you&apos;re dealing with:
            </p>
          </div>

          {/* Pain Points Grid */}
          <div 
            ref={cardsRef}
            className="grid sm:grid-cols-2 lg:grid-cols-4 gap-6"
          >
            {painPoints.map((point, index) => (
              <div
                key={index}
                className="problem-card feature-card group relative overflow-hidden"
              >
                {/* Icon */}
                <div className="icon-circle mb-5 group-hover:bg-zaf-gold/10 group-hover:border-zaf-gold/40 transition-all duration-300">
                  <point.icon className="w-6 h-6 text-zaf-gold" />
                </div>

                {/* Content */}
                <h3 className="text-lg font-semibold text-zaf-text mb-2">
                  {point.title}
                </h3>
                <p className="text-sm text-zaf-text-muted mb-4 leading-relaxed">
                  {point.description}
                </p>

                {/* Solution badge */}
                <div className="flex items-center gap-2 pt-4 border-t border-white/5">
                  <div className="w-1.5 h-1.5 rounded-full bg-zaf-gold animate-pulse" />
                  <span className="text-xs font-medium text-zaf-gold">
                    {point.solution}
                  </span>
                </div>

                {/* Hover glow */}
                <div className="absolute -inset-px bg-gradient-to-br from-zaf-gold/0 to-zaf-gold/0 group-hover:from-zaf-gold/5 group-hover:to-transparent rounded-2xl transition-all duration-500 -z-10" />
              </div>
            ))}
          </div>

          {/* Bottom stat */}
          <div className="mt-16 text-center">
            <div className="inline-flex items-center gap-3 px-6 py-3 rounded-full bg-zaf-navy/30 border border-white/5">
              <span className="text-3xl font-bold text-zaf-gold">40%</span>
              <span className="text-sm text-zaf-text-muted">of finance time wasted on manual tasks</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default Problem;
