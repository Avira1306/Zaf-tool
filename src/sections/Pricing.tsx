import { useEffect, useRef, useState } from 'react';
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { Check, Mail } from 'lucide-react';

gsap.registerPlugin(ScrollTrigger);

const SOLO_LINK = 'https://rzp.io/rzp/zHqFzGcq';
const CONTACT_EMAIL = 'abhishek.bhandari@zaftool.com';

const Pricing = () => {
  const sectionRef = useRef<HTMLElement>(null);
  const [planType, setPlanType] = useState<'individual' | 'firmEnterprise'>('individual');

  useEffect(() => {
    const ctx = gsap.context(() => {
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

      gsap.fromTo(
        '.pricing-card',
        { y: 40, opacity: 0 },
        {
          y: 0,
          opacity: 1,
          duration: 0.6,
          stagger: 0.1,
          scrollTrigger: {
            trigger: '.pricing-grid',
            start: 'top 80%',
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
      <div className="absolute inset-0 bg-zaf-navy-darker" />
      
      <div className="relative z-10 w-full section-padding">
        <div className="max-w-7xl mx-auto">
          <div className="pricing-header text-center mb-16">
            <span className="label-mono mb-4 block">PRICING</span>
            <h2 className="heading-lg text-zaf-text mb-4">
              Simple, Transparent{' '}
              <span className="text-gradient-gold">Pricing</span>
            </h2>
            <p className="body-md max-w-xl mx-auto mb-8">
              Choose the plan that works best for your financial modeling needs.
            </p>

            {/* Plan Type Toggle */}
            <div className="inline-flex items-center gap-4 p-1.5 bg-white/[0.03] rounded-2xl">
              <button
                onClick={() => setPlanType('individual')}
                className={`px-6 py-2.5 rounded-xl text-sm font-semibold transition-all duration-300 ${
                  planType === 'individual'
                    ? 'bg-zaf-gold text-zaf-navy-darker shadow-lg'
                    : 'text-zaf-text-muted hover:text-zaf-text'
                }`}
              >
                Individual
              </button>
              <button
                onClick={() => setPlanType('firmEnterprise')}
                className={`px-6 py-2.5 rounded-xl text-sm font-semibold transition-all duration-300 ${
                  planType === 'firmEnterprise'
                    ? 'bg-zaf-gold text-zaf-navy-darker shadow-lg'
                    : 'text-zaf-text-muted hover:text-zaf-text'
                }`}
              >
                Firm &amp; Enterprise
              </button>
            </div>
          </div>

          {/* Individual: Solo Only */}
          {planType === 'individual' && (
            <div className="pricing-grid max-w-md mx-auto">
              <div className="pricing-card relative p-8 md:p-10 rounded-2xl border border-white/10 bg-white/[0.02] hover:border-white/20 transition-all duration-300">
                <div className="mb-8 text-center">
                  <h3 className="text-2xl font-bold text-zaf-text mb-1">Solo</h3>
                  <p className="text-sm text-zaf-text-muted mb-6">For individual FDD practitioners</p>
                  <div className="flex items-baseline justify-center gap-1 mb-1">
                    <span className="text-5xl font-bold text-zaf-text">$29</span>
                    <span className="text-zaf-text-muted">/ month</span>
                  </div>
                  <p className="text-xs text-zaf-text-muted">No commitment &middot; Cancel anytime</p>
                </div>

                <div className="space-y-3 mb-8">
                  {[
                    'Full P&L, Balance Sheet, NWC & Cash Flow analysis',
                    'AI commentary on every financial statement',
                    'Management Questions generation',
                    'Anomaly & Quality of Earnings detection',
                    'Word & PowerPoint export',
                    'Up to 13 full due diligence runs/month',
                  ].map((feature, i) => (
                    <div key={i} className="flex items-start gap-3">
                      <Check className="w-4 h-4 text-zaf-gold flex-shrink-0 mt-1" />
                      <span className="text-sm text-zaf-text-muted">{feature}</span>
                    </div>
                  ))}
                </div>

                <a
                  href={SOLO_LINK}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="block w-full text-center py-3 rounded-xl font-semibold bg-zaf-gold text-zaf-navy-darker hover:bg-zaf-gold/90 transition-all duration-300"
                >
                  Get Started
                </a>
              </div>
            </div>
          )}

          {/* Firm & Enterprise: Pro + Enterprise side by side */}
          {planType === 'firmEnterprise' && (
            <div className="pricing-grid grid md:grid-cols-2 gap-6 max-w-4xl mx-auto">
              {/* Pro Card */}
              <div className="pricing-card relative p-8 md:p-10 rounded-2xl border border-zaf-gold bg-white/[0.05] shadow-[0_0_40px_-15px_rgba(212,175,55,0.3)] transition-all duration-300">
                <div className="absolute -top-4 left-1/2 -translate-x-1/2 px-4 py-1 bg-zaf-gold rounded-full">
                  <span className="text-xs font-bold text-zaf-navy-darker uppercase tracking-wider">
                    Most Popular
                  </span>
                </div>

                <div className="mb-8 text-center">
                  <h3 className="text-2xl font-bold text-zaf-text mb-1">Pro</h3>
                  <p className="text-sm text-zaf-text-muted mb-6">For transaction advisory teams</p>
                  <div className="flex items-baseline justify-center gap-1 mb-1">
                    <span className="text-5xl font-bold text-zaf-text">$189</span>
                    <span className="text-zaf-text-muted">/ month</span>
                  </div>
                  <p className="text-xs text-zaf-text-muted">No commitment &middot; Cancel anytime</p>
                </div>

                <div className="space-y-3 mb-8">
                  <div className="flex items-start gap-3">
                    <Check className="w-4 h-4 text-zaf-gold flex-shrink-0 mt-1" />
                    <span className="text-sm text-zaf-text-muted font-semibold">Everything in Solo, plus:</span>
                  </div>
                  {[
                    '5 seats for your team',
                    'Advanced AI on every analysis',
                    'Up to 68 full due diligence runs/month',
                    'Priority processing',
                    'Email support',
                  ].map((feature, i) => (
                    <div key={i} className="flex items-start gap-3">
                      <Check className="w-4 h-4 text-zaf-gold flex-shrink-0 mt-1" />
                      <span className="text-sm text-zaf-text-muted">{feature}</span>
                    </div>
                  ))}
                </div>

                <a
                  href={`mailto:${CONTACT_EMAIL}?subject=Book%20a%2030-Day%20Pilot%20-%20Pro%20Plan&body=Hi%20Abhishek%2C%0A%0AI'm%20interested%20in%20booking%20a%2030-day%20pilot%20of%20the%20ZAF%20Tools%20Pro%20plan.%0A%0ABest%20regards`}
                  className="block w-full text-center py-3 rounded-xl font-semibold bg-zaf-gold text-zaf-navy-darker hover:bg-zaf-gold/90 transition-all duration-300"
                >
                  Book a 30-Day Pilot
                </a>
              </div>

              {/* Enterprise Card */}
              <div className="pricing-card relative p-8 md:p-10 rounded-2xl border border-white/10 bg-white/[0.02] hover:border-white/20 transition-all duration-300">
                <div className="mb-8 text-center">
                  <h3 className="text-2xl font-bold text-zaf-text mb-1">Enterprise</h3>
                  <p className="text-sm text-zaf-text-muted mb-6">For Big 4 and mid-tier firms</p>
                  <div className="flex items-baseline justify-center gap-1 mb-1">
                    <span className="text-5xl font-bold text-zaf-text">Custom</span>
                  </div>
                </div>

                <div className="space-y-3 mb-8">
                  <div className="flex items-start gap-3">
                    <Check className="w-4 h-4 text-zaf-gold flex-shrink-0 mt-1" />
                    <span className="text-sm text-zaf-text-muted font-semibold">Everything in Pro, plus:</span>
                  </div>
                  {[
                    'Unlimited seats',
                    'Dedicated onboarding',
                    'Custom workflows',
                    'SLA-backed support',
                  ].map((feature, i) => (
                    <div key={i} className="flex items-start gap-3">
                      <Check className="w-4 h-4 text-zaf-gold flex-shrink-0 mt-1" />
                      <span className="text-sm text-zaf-text-muted">{feature}</span>
                    </div>
                  ))}
                </div>

                <a
                  href={`mailto:${CONTACT_EMAIL}?subject=Enterprise%20Inquiry%20for%20ZAF%20Tools&body=Hi%20Abhishek%2C%0A%0AI'm%20interested%20in%20learning%20more%20about%20the%20Enterprise%20plan%20for%20ZAF%20Tools.%0A%0ABest%20regards`}
                  className="block w-full text-center py-3 rounded-xl font-semibold border border-zaf-gold text-zaf-gold hover:bg-zaf-gold hover:text-zaf-navy-darker transition-all duration-300"
                >
                  <span className="flex items-center justify-center gap-2">
                    <Mail className="w-4 h-4" />
                    Contact Us
                  </span>
                </a>
              </div>
            </div>
          )}

          <div className="mt-12 text-center">
            <p className="text-sm text-zaf-text-muted italic">
              &ldquo;Used by FDD professionals at boutique advisory firms across US, UK, UAE and India.&rdquo;
            </p>
          </div>
        </div>
      </div>
    </section>
  );
};

export default Pricing;
