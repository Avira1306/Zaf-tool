import { useEffect, useRef, useState } from 'react';
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { Play, Shield, Clock, Headphones, Check, Sparkles } from 'lucide-react';

gsap.registerPlugin(ScrollTrigger);

const Hero = () => {
  const sectionRef = useRef<HTMLElement>(null);
  const contentRef = useRef<HTMLDivElement>(null);
  const imageRef = useRef<HTMLDivElement>(null);
  const [email, setEmail] = useState('');
  const [isSubmitted, setIsSubmitted] = useState(false);

  useEffect(() => {
    const ctx = gsap.context(() => {
      // Initial load animation
      const tl = gsap.timeline({ defaults: { ease: 'power3.out' } });
      
      tl.fromTo(
        imageRef.current,
        { x: -60, opacity: 0 },
        { x: 0, opacity: 1, duration: 0.9 }
      )
      .fromTo(
        contentRef.current?.querySelectorAll('.animate-item') || [],
        { y: 40, opacity: 0 },
        { y: 0, opacity: 1, duration: 0.6, stagger: 0.08 },
        '-=0.5'
      );

      // Scroll-triggered animation
      ScrollTrigger.create({
        trigger: sectionRef.current,
        start: 'top top',
        end: '+=100%',
        pin: true,
        scrub: 0.5,
        onUpdate: (self) => {
          const progress = self.progress;
          if (progress > 0.7) {
            const exitProgress = (progress - 0.7) / 0.3;
            gsap.to(imageRef.current, {
              x: -18 * exitProgress + 'vw',
              scale: 1 - 0.04 * exitProgress,
              opacity: 1 - 0.65 * exitProgress,
              duration: 0.1,
            });
            gsap.to(contentRef.current, {
              x: 18 * exitProgress + 'vw',
              scale: 1 - 0.04 * exitProgress,
              opacity: 1 - 0.65 * exitProgress,
              duration: 0.1,
            });
          }
        },
        onLeaveBack: () => {
          gsap.to([imageRef.current, contentRef.current], {
            x: 0,
            scale: 1,
            opacity: 1,
            duration: 0.3,
          });
        },
      });
    }, sectionRef);

    return () => ctx.revert();
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (email) {
      try {
        await fetch('https://formspree.io/f/xeerbjek', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email }),
        });
      } catch (err) {
        console.error('Formspree error:', err);
      }
      setIsSubmitted(true);
      const link = document.createElement('a');
      link.href = '/ZAF_tools_Suite.xlam';
      link.download = 'ZAF_tools_Suite.xlam';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      setTimeout(() => setIsSubmitted(false), 3000);
      setEmail('');
    }
  };

  const handleWatchDemo = () => {
    const demoSection = document.getElementById('demo');
    if (demoSection) {
      demoSection.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const trustBadges = [
    { icon: Clock, text: '14-Day Free Trial' },
    { icon: Shield, text: '14-Day Money-Back' },
    { icon: Headphones, text: 'Founder Support' },
    { icon: Check, text: 'Excel 2016-365' },
  ];

  const trustedBy = ['FDD Professionals', 'M&A Advisors', 'CA Firms', 'IB Analysts', 'Corporate Finance'];

  return (
    <section
      ref={sectionRef}
      id="hero"
      className="hero-section relative min-h-screen flex items-center pt-20 pb-16 overflow-hidden"
    >
      {/* Background gradient */}
      <div className="absolute inset-0 bg-gradient-to-br from-zaf-navy-darker via-zaf-navy-dark to-zaf-navy-darker" />
      
      {/* Subtle grid pattern */}
      <div 
        className="absolute inset-0 opacity-[0.03]"
        style={{
          backgroundImage: `linear-gradient(rgba(201, 168, 76, 0.5) 1px, transparent 1px),
                            linear-gradient(90deg, rgba(201, 168, 76, 0.5) 1px, transparent 1px)`,
          backgroundSize: '60px 60px',
        }}
      />

      <div className="relative z-10 w-full section-padding">
        <div className="grid lg:grid-cols-2 gap-12 lg:gap-16 items-center max-w-7xl mx-auto">
          {/* Left: Product Image */}
          <div 
            ref={imageRef}
            className="relative order-2 lg:order-1"
          >
            <div className="gradient-border p-1">
              <div className="relative rounded-2xl overflow-hidden bg-zaf-navy-dark/50">
                {/* Excel UI Mockup */}
                <div className="aspect-[4/3] bg-gradient-to-br from-[#1F497D]/20 to-[#0B0F17] p-6">
                  {/* Ribbon */}
                  <div className="flex gap-1 mb-4">
                    <div className="px-4 py-2 bg-zaf-navy text-white text-xs font-medium rounded-t">File</div>
                    <div className="px-4 py-2 bg-zaf-gold text-zaf-navy-darker text-xs font-medium rounded-t">Home</div>
                    <div className="px-4 py-2 bg-zaf-navy/50 text-white/70 text-xs font-medium rounded-t">Insert</div>
                    <div className="px-4 py-2 bg-zaf-navy/50 text-white/70 text-xs font-medium rounded-t">Page Layout</div>
                    <div className="px-4 py-2 bg-zaf-navy/50 text-white/70 text-xs font-medium rounded-t">Formulas</div>
                    <div className="px-4 py-2 bg-zaf-gold text-zaf-navy-darker text-xs font-medium rounded-t flex items-center gap-1">
                      <Sparkles className="w-3 h-3" />
                      ZAF Tools
                    </div>
                  </div>
                  
                  {/* Toolbar */}
                  <div className="flex gap-2 mb-4 flex-wrap">
                    <div className="px-3 py-1.5 bg-zaf-navy/60 rounded text-xs text-white/80">Format</div>
                    <div className="px-3 py-1.5 bg-zaf-navy/60 rounded text-xs text-white/80">Navigate</div>
                    <div className="px-3 py-1.5 bg-zaf-navy/60 rounded text-xs text-white/80">Audit</div>
                    <div className="px-3 py-1.5 bg-zaf-gold/20 border border-zaf-gold/40 rounded text-xs text-zaf-gold">AI Model</div>
                    <div className="px-3 py-1.5 bg-zaf-navy/60 rounded text-xs text-white/80">Clean</div>
                  </div>
                  
                  {/* Spreadsheet Grid */}
                  <div className="border border-white/10 rounded-lg overflow-hidden">
                    <div className="grid grid-cols-6 gap-px bg-white/10">
                      {Array.from({ length: 24 }).map((_, i) => (
                        <div 
                          key={i} 
                          className={`h-8 flex items-center justify-center text-xs ${
                            i === 5 || i === 11 || i === 17 ? 'bg-zaf-gold/20 text-zaf-gold' : 'bg-zaf-navy-dark/80 text-white/60'
                          }`}
                        >
                          {i === 5 ? '$1.2M' : i === 11 ? '8.5%' : i === 17 ? '✓' : Math.floor(Math.random() * 1000)}
                        </div>
                      ))}
                    </div>
                  </div>
                  
                  {/* AI Panel */}
                  <div className="mt-4 p-4 bg-zaf-navy/40 rounded-lg border border-zaf-gold/20">
                    <div className="flex items-center gap-2 mb-2">
                      <Sparkles className="w-4 h-4 text-zaf-gold" />
                      <span className="text-xs font-medium text-zaf-gold">Ask Zaffy</span>
                    </div>
                    <div className="text-xs text-white/60">"Build a 3-statement model for Q4..."</div>
                  </div>
                </div>
                
                {/* Glow effect */}
                <div className="absolute -inset-1 bg-gradient-to-r from-zaf-gold/20 via-transparent to-zaf-navy/20 blur-2xl -z-10" />
              </div>
            </div>
          </div>

          {/* Right: Content */}
          <div ref={contentRef} className="order-1 lg:order-2">
            <div className="animate-item">
              <span className="label-mono mb-4 block">EXCEL ADD-IN + AI SUITE</span>
            </div>
            
            <h1 className="animate-item heading-xl text-zaf-text mb-6">
              30+ Excel Tools +{' '}
              <span className="text-gradient-gold">AI</span> That Builds Your Financial Models
            </h1>
            
            <p className="animate-item body-lg mb-8 max-w-xl">
              Built by a 15-year FDD practitioner. 
              ZAF Core handles the grunt work. ZAF AI thinks like an analyst.
            </p>

            {/* Email Capture Form */}
            <form onSubmit={handleSubmit} className="animate-item mb-6">
              <div className="flex flex-col sm:flex-row gap-3">
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="Enter your work email"
                  className="input-zaf flex-1"
                  required
                />
                <button type="submit" className="btn-gold whitespace-nowrap">
                  {isSubmitted ? 'Check your email!' : 'Start Free Trial — No Card'}
                </button>
              </div>
            </form>

            {/* Secondary CTA */}
            <div className="animate-item mb-8">
              <button onClick={handleWatchDemo} className="flex items-center gap-2 text-zaf-text-muted hover:text-zaf-gold transition-colors">
                <div className="w-10 h-10 rounded-full bg-zaf-navy/50 flex items-center justify-center border border-white/10">
                  <Play className="w-4 h-4 ml-0.5" />
                </div>
                <span className="text-sm font-medium">Watch 2-Min Demo</span>
              </button>
            </div>

            {/* Trust Badges */}
            <div className="animate-item mb-6">
              <div className="trust-bar">
                {trustBadges.map((badge, index) => (
                  <div key={index} className="trust-badge">
                    <badge.icon className="w-4 h-4 text-zaf-gold" />
                    <span>{badge.text}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Trusted By */}
            <div className="animate-item">
              <p className="text-xs text-zaf-text-muted mb-3 text-center sm:text-left">Trusted by:</p>
              <div className="logo-bar">
                {trustedBy.map((company, index) => (
                  <span key={index} className="logo-item">
                    {company}
                    {index < trustedBy.length - 1 && (
                      <span className="text-zaf-gold/50 ml-1.5">•</span>
                    )}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Bottom gradient fade */}
      <div className="absolute bottom-0 left-0 right-0 h-32 bg-gradient-to-t from-zaf-navy-darker to-transparent" />
    </section>
  );
};

export default Hero;
