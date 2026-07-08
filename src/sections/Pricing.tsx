import { useEffect, useRef, useState } from 'react';
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { Check, Mail } from 'lucide-react';

gsap.registerPlugin(ScrollTrigger);

const CONTACT_EMAIL = 'abhishek.bhandari@zaftool.com';
const API_BASE = 'https://zaf-backend-production.up.railway.app';

const tiers = [
  {
    name: 'Solo',
    tagline: 'For individual FDD practitioners',
    priceUsd: '$29',
    priceInr: '₹2,499',
    period: '/ month',
    notice: 'No commitment · Cancel anytime',
    planIdUsd: 'plan_TADViBAtxX1Qyf',
    planIdInr: 'plan_TB07qPNwwdrGDp',
    features: [
      'Full P&L, Balance Sheet, NWC & Cash Flow analysis',
      'AI commentary on every financial statement',
      'Management Questions generation',
      'Anomaly & Quality of Earnings detection',
      'Word & PowerPoint export',
      'Up to 13 full due diligence runs/month',
    ],
    cta: 'Get Started',
    highlight: false,
    badge: null,
    ctaOutline: false,
  },
  {
    name: 'Pro',
    tagline: 'For transaction advisory teams',
    priceUsd: '$189',
    priceInr: '₹15,999',
    period: '/ month',
    notice: 'No commitment · Cancel anytime',
    features: [
      'Everything in Solo, plus:',
      '5 seats for your team',
      'Advanced AI on every analysis',
      'Up to 68 full due diligence runs/month',
      'Priority processing',
      'Email support',
    ],
    cta: 'Book a 30-Day Pilot',
    highlight: true,
    badge: 'Most Popular',
    ctaOutline: false,
  },
  {
    name: 'Enterprise',
    tagline: 'For Big 4 and mid-tier firms',
    priceUsd: 'Custom',
    priceInr: 'Custom',
    period: '',
    notice: '',
    features: [
      'Everything in Pro, plus:',
      'Unlimited seats',
      'Dedicated onboarding',
      'Custom workflows',
      'SLA-backed support',
    ],
    cta: 'Contact Us',
    highlight: false,
    badge: null,
    ctaOutline: true,
  },
];

const Pricing = () => {
  const sectionRef = useRef<HTMLElement>(null);
  const [region, setRegion] = useState<'india' | 'international'>('international');

  const handleBuyNow = async (planId: string) => {
    try {
      const response = await fetch(`${API_BASE}/razorpay/create-subscription`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ planId }),
      });
      const data = await response.json();
      if (data.subscriptionUrl) {
        window.location.href = data.subscriptionUrl;
      } else {
        alert('Something went wrong. Please try again.');
      }
    } catch (err) {
      alert('Network error. Please try again.');
    }
  };

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
              Choose the plan that works best for your financial due diligence needs.
            </p>

            {/* Region Toggle */}
            <div className="inline-flex items-center gap-1 p-1 bg-white/[0.05] rounded-2xl">
              <button
                onClick={() => setRegion('international')}
                className={`px-5 py-2 rounded-xl text-sm font-semibold transition-all duration-300 ${
                  region === 'international'
                    ? 'bg-zaf-gold text-zaf-navy-darker shadow-lg'
                    : 'text-zaf-text-muted hover:text-zaf-text'
                }`}
              >
                Outside India
              </button>
              <button
                onClick={() => setRegion('india')}
                className={`px-5 py-2 rounded-xl text-sm font-semibold transition-all duration-300 ${
                  region === 'india'
                    ? 'bg-zaf-gold text-zaf-navy-darker shadow-lg'
                    : 'text-zaf-text-muted hover:text-zaf-text'
                }`}
              >
                India
              </button>
            </div>
          </div>

          <div className="pricing-grid grid md:grid-cols-3 gap-6">
            {tiers.map((tier, index) => (
              <div
                key={index}
                className={`pricing-card relative p-8 md:p-10 rounded-2xl transition-all duration-300 flex flex-col ${
                  tier.highlight
                    ? 'border border-zaf-gold bg-white/[0.05] shadow-[0_0_40px_-15px_rgba(212,175,55,0.3)] scale-[1.02] md:scale-105'
                    : 'border border-white/10 bg-white/[0.03] hover:border-white/20'
                }`}
              >
                {tier.badge && (
                  <div className="absolute -top-4 left-1/2 -translate-x-1/2 px-4 py-1 bg-zaf-gold rounded-full">
                    <span className="text-xs font-bold text-zaf-navy-darker uppercase tracking-wider">
                      {tier.badge}
                    </span>
                  </div>
                )}

                <div className="mb-6 text-center">
                  <h3 className="text-2xl font-bold text-zaf-text mb-1">{tier.name}</h3>
                  <p className="text-sm text-zaf-text-muted mb-6">{tier.tagline}</p>
                  <div className="flex items-baseline justify-center gap-1 mb-1">
                    <span className="text-5xl font-bold text-zaf-text">
                      {region === 'india' && tier.priceInr ? tier.priceInr : tier.priceUsd}
                    </span>
                    {tier.period && <span className="text-zaf-text-muted">{tier.period}</span>}
                  </div>
                  {tier.notice && (
                    <p className="text-xs text-zaf-text-muted">{tier.notice}</p>
                  )}
                </div>

                <div className="space-y-3 mb-8 flex-1">
                  {tier.features.map((feature, fIndex) => (
                    <div key={fIndex} className="flex items-start gap-3">
                      <Check className="w-4 h-4 text-zaf-gold flex-shrink-0 mt-1" />
                      <span className={`text-sm ${fIndex === 0 && tier.highlight ? 'text-zaf-text font-semibold' : 'text-zaf-text-muted'}`}>
                        {feature}
                      </span>
                    </div>
                  ))}
                </div>

                {tier.ctaOutline ? (
                  <a
                    href={`mailto:${CONTACT_EMAIL}?subject=${encodeURIComponent('Enterprise Inquiry - ZAF Tools')}`}
                    className="block w-full text-center py-3 rounded-xl font-semibold border border-zaf-gold text-zaf-gold hover:bg-zaf-gold hover:text-zaf-navy-darker transition-all duration-300"
                  >
                    <span className="flex items-center justify-center gap-2">
                      <Mail className="w-4 h-4" />
                      {tier.cta}
                    </span>
                  </a>
                ) : tier.name === 'Solo' ? (
                  <button
                    onClick={() => handleBuyNow(region === 'india' ? tier.planIdInr : tier.planIdUsd)}
                    className="block w-full text-center py-3 rounded-xl font-semibold bg-zaf-gold text-zaf-navy-darker hover:bg-zaf-gold/90 transition-all duration-300"
                  >
                    {tier.cta}
                  </button>
                ) : (
                  <a
                    href={`mailto:${CONTACT_EMAIL}?subject=${encodeURIComponent('Book a 30-Day Pilot - Pro Plan')}&body=${encodeURIComponent('Hi Abhishek,\n\nI\'m interested in booking a 30-day pilot of the ZAF Tools Pro plan.\n\nBest regards')}`}
                    className="block w-full text-center py-3 rounded-xl font-semibold bg-zaf-gold text-zaf-navy-darker hover:bg-zaf-gold/90 transition-all duration-300"
                  >
                    {tier.cta}
                  </a>
                )}
              </div>
            ))}
          </div>

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
