import { useEffect, useRef, useState } from 'react';
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { Check, Mail } from 'lucide-react';

gsap.registerPlugin(ScrollTrigger);

const Pricing = () => {
  const sectionRef = useRef<HTMLElement>(null);
  const [isAnnual, setIsAnnual] = useState(false);

  const tiers = [
    {
      name: 'Starter',
      monthlyPrice: '$8',
      annualPrice: '$77',
      annualSavings: 'Save 20%',
      seats: '1 user',
      description: 'For consultants running occasional deals.',
      features: [
        'Full ZAF Tools suite — 30+ built-in FDD productivity tools',
        'Auto-generate P&L, Balance Sheet, Cash Flow & NWC from trial balance',
        'AI-written FDD commentary with observations and watch items',
        'Management Questions generator',
        '1 device per user',
        'Email support',
      ],
      cta: 'Buy Now',
      highlight: false,
      planId: 'plan_T6uf7mQTXBT1yh',
      annualPlanId: 'plan_T6uhZ95zmWBP8C',
    },
    {
      name: 'Solo',
      monthlyPrice: '$19',
      annualPrice: '$182',
      annualSavings: 'Save 20%',
      seats: '1 user',
      description: 'For active practitioners on 2-4 live deals.',
      features: [
        'Everything in Starter',
        'Faster AI model — richer commentary and deeper observations',
        'PDF trial balance ingestion — text and scanned documents',
        'EBITDA Bridge, Anomaly Detection, AI-suggested Adjustments',
        'Sector-specific AI intelligence across 8 industry verticals',
        'Email support',
      ],
      cta: 'Buy Now',
      highlight: false,
      planId: 'plan_T6uiSaazrNc0S1',
      annualPlanId: 'plan_T6ujIMdIIpMHXk',
    },
    {
      name: 'Pro',
      monthlyPrice: '$30',
      annualPrice: '$288',
      annualSavings: 'Save 20%',
      seats: '1 user',
      description: 'For senior practitioners who need the best output quality.',
      features: [
        'Everything in Solo',
        'Premium AI model — significantly better commentary quality',
        'Full FDD workflow — MQ, adjustments, anomalies, EBITDA Bridge',
        'Diligence Library — 28 built-in FDD reference formats',
        'PPT and Word export of FDD schedules and commentary',
        'Priority support',
      ],
      cta: 'Buy Now',
      highlight: true,
      planId: 'plan_T6v4GBp2ctVmHh',
      annualPlanId: 'plan_T6uyjDHdLSFCD9',
    },
    {
      name: 'Enterprise',
      monthlyPrice: 'Custom',
      annualPrice: 'Custom',
      annualSavings: '',
      seats: 'Unlimited',
      description: 'For TAS teams and advisory firms.',
      features: [
        'Dedicated seats for your team (3 to 50+)',
        'Azure OpenAI endpoint — stays within your Microsoft data boundary',
        'Custom deal templates and FDD library',
        'Dedicated onboarding and implementation support',
        'Volume pricing',
      ],
      cta: 'Contact Sales',
      highlight: false,
      planId: '',
      annualPlanId: '',
    },
  ];

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

  const getPrice = (tier: typeof tiers[0]) => {
    return isAnnual ? tier.annualPrice : tier.monthlyPrice;
  };

  const getSavings = (tier: typeof tiers[0]) => {
    return isAnnual ? tier.annualSavings : '';
  };

  const API_BASE = 'https://zaf-backend-production.up.railway.app';

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

            {/* Billing Toggle */}
            <div className="flex items-center justify-center gap-4">
              <span className={`text-sm font-semibold ${!isAnnual ? 'text-zaf-text' : 'text-zaf-text-muted'}`}>
                Monthly
              </span>
              <button
                onClick={() => setIsAnnual(!isAnnual)}
                className={`relative inline-flex h-8 w-14 items-center rounded-full transition-colors ${
                  isAnnual ? 'bg-zaf-gold' : 'bg-white/10'
                }`}
              >
                <span
                  className={`inline-block h-6 w-6 transform rounded-full bg-zaf-navy-darker transition-transform ${
                    isAnnual ? 'translate-x-7' : 'translate-x-1'
                  }`}
                />
              </button>
              <span className={`text-sm font-semibold ${isAnnual ? 'text-zaf-text' : 'text-zaf-text-muted'}`}>
                Annual
              </span>
              {isAnnual && (
                <span className="ml-4 px-3 py-1 bg-zaf-gold/20 text-zaf-gold rounded-full text-xs font-bold">
                  Save up to 36%
                </span>
              )}
            </div>
          </div>

          <div className="pricing-grid grid md:grid-cols-4 gap-6">
            {tiers.map((tier, index) => (
              <div
                key={index}
                className={`pricing-card relative p-8 rounded-2xl border transition-all duration-300 ${
                  tier.highlight
                    ? 'bg-white/[0.05] border-zaf-gold shadow-[0_0_40px_-15px_rgba(212,175,55,0.3)] md:scale-105'
                    : 'bg-white/[0.02] border-white/10 hover:border-white/20'
                }`}
              >
                {tier.highlight && (
                  <div className="absolute -top-4 left-1/2 -translate-x-1/2 px-4 py-1 bg-zaf-gold rounded-full">
                    <span className="text-xs font-bold text-zaf-navy-darker uppercase tracking-wider">
                      Most Popular
                    </span>
                  </div>
                )}

                <div className="mb-8">
                  <h3 className="text-xl font-bold text-zaf-text mb-1">{tier.name}</h3>
                  <p className="text-xs text-zaf-gold mb-3 font-semibold">{tier.seats}</p>
                  <div className="flex items-baseline gap-1 mb-2">
                    <span className="text-4xl font-bold text-zaf-text">{getPrice(tier)}</span>
                    {tier.monthlyPrice !== 'Custom' && (
                      <span className="text-zaf-text-muted">{isAnnual ? '/ year' : '/ month'}</span>
                    )}
                  </div>
                  {getSavings(tier) && (
                    <p className="text-xs text-zaf-gold font-semibold mb-2">{getSavings(tier)}</p>
                  )}
                  <p className="text-sm text-zaf-text-muted">{tier.description}</p>
                </div>

                <div className="space-y-3 mb-8">
                  {tier.features.map((feature, fIndex) => (
                    <div key={fIndex} className="flex items-start gap-3">
                      <Check className="w-4 h-4 text-zaf-gold flex-shrink-0 mt-1" />
                      <span className="text-sm text-zaf-text-muted">{feature}</span>
                    </div>
                  ))}
                </div>

                {tier.name === 'Enterprise' ? (
                  <a
                    href="mailto:Abhishek.bhandari@zaftool.com?subject=Enterprise%20Inquiry%20for%20ZAF%20Tools&body=Hi%20Abhishek%2C%0A%0AI'm%20interested%20in%20learning%20more%20about%20the%20Enterprise%20plan%20for%20ZAF%20Tools.%20We%20have%20a%20team%20and%20would%20like%20to%20discuss%20volume%20licensing.%0A%0ABest%20regards"
                    className="btn-outline w-full flex items-center justify-center gap-2 py-3 rounded-xl font-semibold border border-zaf-gold text-zaf-gold hover:bg-zaf-gold hover:text-zaf-navy-darker transition-all duration-300"
                  >
                    <Mail className="w-4 h-4" />
                    {tier.cta}
                  </a>
                ) : (
                  <div className="space-y-3">
                    <button
                      onClick={() => handleBuyNow(isAnnual ? tier.annualPlanId : tier.planId)}
                      className={`w-full flex items-center justify-center gap-2 py-3 rounded-xl font-semibold transition-all duration-300 ${
                        tier.highlight
                          ? 'bg-zaf-gold text-zaf-navy-darker hover:bg-zaf-gold/90'
                          : 'bg-white/10 text-zaf-text hover:bg-white/20'
                      }`}
                    >
                      {tier.cta}
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>

          <div className="mt-12 text-center">
            <p className="text-sm text-zaf-text-muted italic">
              "Used by FDD professionals at boutique advisory firms across US, UK, UAE and India."
            </p>
          </div>
        </div>
      </div>
    </section>
  );
};

export default Pricing;
