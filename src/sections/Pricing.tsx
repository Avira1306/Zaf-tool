import { useEffect, useRef, useState } from 'react';
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { Check, Download, Mail } from 'lucide-react';
import BuyNowButton from '../components/BuyNowButton';

gsap.registerPlugin(ScrollTrigger);

const Pricing = () => {
  const sectionRef = useRef<HTMLElement>(null);
  const [isAnnual, setIsAnnual] = useState(false);

  const tiers = [
    {
      name: 'Solo',
      monthlyPrice: '$19',
      annualPrice: '$149',
      annualSavings: '35% off',
      seats: '1 user',
      description: 'Perfect for individual analysts.',
      features: [
        'ZAF Core (30+ tools)',
        'ZAF AI (all features)',
        '1 device per user',
        'All future updates',
        'Email support',
      ],
      cta: 'Start Free Trial',
      highlight: false,
    },
    {
      name: 'Team',
      monthlyPrice: '$49',
      annualPrice: '$399',
      annualSavings: '32% off',
      seats: '3 seats',
      description: 'Ideal for small deal teams.',
      features: [
        'ZAF Core (30+ tools)',
        'ZAF AI (all features)',
        '3 user seats',
        'Multi-device access',
        'All future updates',
        'Priority email support',
        '14-day money-back',
      ],
      cta: 'Start Free Trial',
      highlight: true,
    },
    {
      name: 'Firm',
      monthlyPrice: '$129',
      annualPrice: '$999',
      annualSavings: '36% off',
      seats: '10 seats',
      description: 'For boutique advisory firms.',
      features: [
        'ZAF Core (30+ tools)',
        'ZAF AI (all features)',
        '10 user seats',
        'Multi-device access',
        'All future updates',
        'Priority support',
        'Onboarding assistance',
        '14-day money-back',
      ],
      cta: 'Start Free Trial',
      highlight: false,
    },
    {
      name: 'Enterprise',
      monthlyPrice: 'Custom',
      annualPrice: 'Custom',
      annualSavings: '',
      seats: 'Unlimited',
      description: 'Team licensing & volume discounts.',
      features: [
        'Everything in Firm',
        'Unlimited user seats',
        'Multi-device access',
        'Priority support',
        'Dedicated onboarding',
        'Custom integrations',
        'Volume pricing available',
      ],
      cta: 'Contact Sales',
      highlight: false,
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

  const getPlanKey = (tierName: string): string => {
    const baseKey = tierName.toLowerCase();
    return isAnnual ? `${baseKey}_annual` : `${baseKey}_monthly`;
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
                    <a
                      href="https://github.com/Avira1306/Zaf-tool/releases/download/v4.2.0/ZAF_Tools_v4.2.0.msi"
                      download
                      target="_blank"
                      rel="noopener noreferrer"
                      className={`w-full flex items-center justify-center gap-2 py-3 rounded-xl font-semibold transition-all duration-300 ${
                        tier.highlight
                          ? 'bg-zaf-gold text-zaf-navy-darker hover:bg-zaf-gold/90'
                          : 'bg-white/10 text-zaf-text hover:bg-white/20'
                      }`}
                    >
                      <Download className="w-4 h-4" />
                      {tier.cta}
                    </a>
                    <BuyNowButton planKey={getPlanKey(tier.name)} />
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
