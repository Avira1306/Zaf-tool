import { useEffect, useRef, useState } from 'react';
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { Check, ArrowRight } from 'lucide-react';

gsap.registerPlugin(ScrollTrigger);

const Pricing = () => {
  const sectionRef = useRef(null);
  const [isAnnual, setIsAnnual] = useState(false);

  const tiers = [
    {
      name: 'Solo',
      monthlyPrice: '$29',
      annualPrice: '$290',
      annualSavings: 'Save 17%',
      seats: '1 user',
      description: 'For individual deal professionals and analysts.',
      features: [
        'Full ZAF Tools suite — 30+ FDD productivity tools',
        'AI-powered FDD commentary & observations',
        'Auto-generate P&L, BS, CF & NWC from TB',
        'EBITDA Bridge + Anomaly Detection',
        'PDF & Image import support',
        'Email support',
      ],
      cta: 'Start Free Trial',
      highlight: false,
      planId: 'plan_T6uiSaazrNc0S1',
      annualPlanId: 'plan_T6ujIMdIIpMHXk',
    },
    {
      name: 'Firm',
      monthlyPrice: '$299',
      annualPrice: '$2990',
      annualSavings: 'Save 17%',
      seats: 'Up to 5 users',
      description: 'For boutique advisory firms and small teams.',
      features: [
        'Everything in Solo',
        'Team access (up to 5 seats)',
        'Priority AI model for better output',
        'Advanced Model Audit Engine',
        'PPT & Word export',
        'Priority email + chat support',
      ],
      cta: 'Start Free Trial',
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
      description: 'For Big 4, large TAS teams & advisory firms.',
      features: [
        'Unlimited seats',
        'Azure OpenAI (data stays in your tenant)',
        'Custom FDD templates & libraries',
        'SSO & advanced security',
        'Dedicated onboarding & support',
        'Volume pricing & custom SLAs',
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

  const getPrice = (tier) => {
    return isAnnual ? tier.annualPrice : tier.monthlyPrice;
  };

  const getSavings = (tier) => {
    return isAnnual ? tier.annualSavings : '';
  };

  const API_BASE = 'https://zaf-backend-production.up.railway.app';

  const handleBuyNow = async (planId) => {
    if (!planId) {
      window.location.href = 'mailto:abhishek.bhandari@zaftool.com?subject=Enterprise%20Inquiry';
      return;
    }
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
    <section ref={sectionRef} id="pricing" className="py-20 bg-zaf-navy text-white">
      <div className="max-w-7xl mx-auto px-6">
        {/* Header */}
        <div className="text-center mb-12 pricing-header">
          <h2 className="text-4xl md:text-5xl font-bold mb-4">
            Simple, Transparent Pricing
          </h2>
          <p className="text-xl text-white/70 max-w-2xl mx-auto">
            Choose the plan that fits how you work. No hidden fees. Cancel anytime.
          </p>
        </div>

        {/* Billing Toggle */}
        <div className="flex justify-center items-center gap-4 mb-10">
          <span className={!isAnnual ? 'font-semibold' : 'text-white/60'}>Monthly</span>
          <button
            onClick={() => setIsAnnual(!isAnnual)}
            className={`relative inline-flex h-8 w-14 items-center rounded-full transition-colors ${isAnnual ? 'bg-zaf-gold' : 'bg-white/10'}`}
          >
            <span className={`inline-block h-6 w-6 transform rounded-full bg-white transition-transform ${isAnnual ? 'translate-x-7' : 'translate-x-1'}`} />
          </button>
          <span className={isAnnual ? 'font-semibold' : 'text-white/60'}>Annual</span>
          {isAnnual && (
            <span className="ml-2 text-sm bg-zaf-gold text-zaf-navy px-3 py-0.5 rounded-full font-medium">
              Save up to 17%
            </span>
          )}
        </div>

        {/* Pricing Cards */}
        <div className="pricing-grid grid md:grid-cols-3 gap-8 max-w-6xl mx-auto">
          {tiers.map((tier, index) => (
            <div
              key={index}
              className={`pricing-card relative bg-white/5 border border-white/10 rounded-2xl p-8 flex flex-col ${tier.highlight ? 'ring-2 ring-zaf-gold scale-[1.02]' : ''}`}
            >
              {tier.highlight && (
                <div className="absolute -top-4 left-1/2 -translate-x-1/2 bg-zaf-gold text-zaf-navy px-4 py-1 rounded-full text-sm font-semibold">
                  Most Popular
                </div>
              )}

              <div className="mb-6">
                <h3 className="text-2xl font-bold">{tier.name}</h3>
                <p className="text-white/60 mt-1">{tier.seats}</p>
              </div>

              <div className="mb-6">
                <div className="flex items-baseline">
                  <span className="text-5xl font-bold tracking-tighter">{getPrice(tier)}</span>
                  {tier.monthlyPrice !== 'Custom' && (
                    <span className="text-white/60 ml-1">/{isAnnual ? 'year' : 'month'}</span>
                  )}
                </div>
                {getSavings(tier) && (
                  <p className="text-zaf-gold text-sm mt-1">{getSavings(tier)}</p>
                )}
              </div>

              <p className="text-white/70 mb-6">{tier.description}</p>

              <ul className="space-y-3 mb-8 flex-1">
                {tier.features.map((feature, fIndex) => (
                  <li key={fIndex} className="flex items-start gap-3">
                    <Check className="w-5 h-5 text-zaf-gold mt-0.5 flex-shrink-0" />
                    <span className="text-sm">{feature}</span>
                  </li>
                ))}
              </ul>

              {tier.name === 'Enterprise' ? (
                <a
                  href="mailto:abhishek.bhandari@zaftool.com?subject=Enterprise%20Inquiry%20for%20ZAF%20Tools"
                  className="w-full flex items-center justify-center gap-2 py-3.5 rounded-xl font-semibold bg-white/10 hover:bg-white/20 transition-all"
                >
                  {tier.cta} <ArrowRight className="w-4 h-4" />
                </a>
              ) : (
                <button
                  onClick={() => handleBuyNow(isAnnual ? tier.annualPlanId : tier.planId)}
                  className={`w-full flex items-center justify-center gap-2 py-3.5 rounded-xl font-semibold transition-all duration-300 ${
                    tier.highlight
                      ? 'bg-zaf-gold text-zaf-navy hover:bg-zaf-gold/90'
                      : 'bg-white/10 text-white hover:bg-white/20'
                  }`}
                >
                  {tier.cta} <ArrowRight className="w-4 h-4" />
                </button>
              )}
            </div>
          ))}
        </div>

        <p className="text-center text-white/50 text-sm mt-10">
          Used by FDD professionals at boutique advisory firms across US, UK, UAE and India.
        </p>
      </div>
    </section>
  );
};

export default Pricing;
