import { useEffect, useRef, useState } from 'react';
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { Check, Sparkles, Download, ExternalLink } from 'lucide-react';

gsap.registerPlugin(ScrollTrigger);

const Pricing = () => {
  const sectionRef = useRef<HTMLElement>(null);
  const [price, setPrice] = useState('');

  const features = [
    'ZAF Core (30+ tools)',
    'ZAF AI (all features)',
    '365 days license',
    '1 device per user',
    'All future updates',
    'Founder support',
    '14-day money-back',
  ];

  useEffect(() => {
    const ctx = gsap.context(() => {
      // Header animation
      gsap.fromTo(
        '.pricing-header',
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

      // Card animation
      gsap.fromTo(
        '.pricing-card-main',
        { scale: 0.95, opacity: 0 },
        {
          scale: 1,
          opacity: 1,
          duration: 0.7,
          scrollTrigger: {
            trigger: '.pricing-card-main',
            start: 'top 75%',
            toggleActions: 'play none none reverse',
          },
        }
      );

      // Features stagger
      gsap.fromTo(
        '.feature-item',
        { x: -20, opacity: 0 },
        {
          x: 0,
          opacity: 1,
          duration: 0.4,
          stagger: 0.05,
          scrollTrigger: {
            trigger: '.features-list',
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
      id="pricing"
      className="relative py-24 lg:py-32 overflow-hidden"
    >
      {/* Background */}
      <div className="absolute inset-0 bg-zaf-navy-darker" />
      
      {/* Gold accent gradient */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-zaf-gold/5 rounded-full blur-3xl" />

      <div className="relative z-10 w-full section-padding">
        <div className="max-w-4xl mx-auto">
          {/* Section Header */}
          <div className="pricing-header text-center mb-12">
            <span className="label-mono mb-4 block">PRICING</span>
            <h2 className="heading-lg text-zaf-text mb-4">
              Pay What You Want.{' '}
              <span className="text-gradient-gold">Seriously.</span>
            </h2>
            <p className="body-md max-w-xl mx-auto">
              Type any amount. You decide what it's worth.
              Everything is included.
            </p>
          </div>

          {/* Pricing Card */}
          <div className="pricing-card-main pricing-highlight">
            <div className="text-center mb-8">
              {/* Badge */}
              <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-zaf-gold/10 border border-zaf-gold/30 mb-6">
                <Sparkles className="w-4 h-4 text-zaf-gold" />
                <span className="text-sm font-medium text-zaf-gold">Inaugural Offer — Pay What It's Worth</span>
              </div>

              {/* Jobs-style free input */}
              <div className="mb-8">
                <div className="flex justify-center items-center gap-2 mb-3">
                  <span className="text-3xl text-zaf-text-muted font-light">$</span>
                  <input
                    type="number"
                    value={price}
                    onChange={(e) => setPrice(e.target.value)}
                    placeholder="___"
                    min="1"
                    className="w-32 text-center text-6xl sm:text-7xl font-bold text-zaf-text bg-transparent border-b-2 border-zaf-gold/40 focus:border-zaf-gold outline-none pb-1"
                    style={{MozAppearance: 'textfield'}}
                  />
                </div>
                <p className="text-sm text-zaf-text-muted">
                  Pay what it's worth to you.{' '}
                  <span className="text-zaf-gold">Most people pay between $49 and $149.</span>
                </p>
              </div>

              {/* CTA */}
              <div className="flex flex-col sm:flex-row gap-4 justify-center items-center">
                <a
                  href="/ZAF_tools_Suite.xlam"
                  download="ZAF_Tools_Suite.xlam"
                  className="btn-outline inline-flex items-center gap-2 text-lg px-8 py-4"
                >
                  <Download className="w-5 h-5" />
                  Start Free Trial
                </a>
                <a
                  href={`https://rzp.io/rzp/zafsuite${price ? `?amount=${price}00` : ''}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="btn-gold inline-flex items-center gap-2 text-lg px-8 py-4"
                >
                  Buy Now
                  <ExternalLink className="w-4 h-4" />
                </a>
              </div>

              <p className="text-xs text-zaf-text-muted mt-4">
                14-day free trial • No credit card required • Pay what you think it's worth
              </p>
            </div>

            {/* Divider */}
            <div className="h-px bg-gradient-to-r from-transparent via-white/10 to-transparent mb-8" />

            {/* Features */}
            <div className="features-list grid sm:grid-cols-2 gap-4">
              {features.map((feature, index) => (
                <div 
                  key={index}
                  className="feature-item flex items-center gap-3"
                >
                  <div className="w-5 h-5 rounded-full bg-zaf-gold/10 flex items-center justify-center flex-shrink-0">
                    <Check className="w-3 h-3 text-zaf-gold" />
                  </div>
                  <span className="text-sm text-zaf-text">{feature}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Trust badges */}
          <div className="mt-10 flex flex-wrap justify-center gap-4">
            <div className="flex items-center gap-2 px-4 py-2 rounded-full bg-white/[0.03] border border-white/5">
              <Check className="w-4 h-4 text-emerald-400" />
              <span className="text-xs text-zaf-text-muted">14-day money-back</span>
            </div>
            <div className="flex items-center gap-2 px-4 py-2 rounded-full bg-white/[0.03] border border-white/5">
              <Check className="w-4 h-4 text-emerald-400" />
              <span className="text-xs text-zaf-text-muted">100% offline for Core</span>
            </div>
            <div className="flex items-center gap-2 px-4 py-2 rounded-full bg-white/[0.03] border border-white/5">
              <Check className="w-4 h-4 text-emerald-400" />
              <span className="text-xs text-zaf-text-muted">Founder support</span>
            </div>
          </div>

          {/* Enterprise note */}
          <div className="mt-10 text-center">
            <p className="text-sm text-zaf-text-muted mb-2">
              Need enterprise licensing or have questions?
            </p>
            <a 
              href="mailto:abhishek.bhandari@zaftool.com"
              className="text-sm text-zaf-gold hover:underline"
            >
              Contact us at abhishek.bhandari@zaftool.com
            </a>
          </div>
        </div>
      </div>
    </section>
  );
};

export default Pricing;
