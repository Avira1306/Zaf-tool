import { useEffect, useRef } from 'react';
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { Check, Download, Mail } from 'lucide-react';

gsap.registerPlugin(ScrollTrigger);

const Pricing = () => {
  const sectionRef = useRef<HTMLElement>(null);

  const handleContactSales = (e: React.MouseEvent) => {
    e.preventDefault();
    const email = "Abhishek.bhandari@zaftool.com";
    const subject = encodeURIComponent("Enterprise Inquiry for ZAF Tools");
    const body = encodeURIComponent("Hi Abhishek,\n\nI'm interested in learning more about the Enterprise plan for ZAF Tools. We have a team of [Number] people and would like to discuss volume licensing.\n\nBest regards,\n[Your Name]");
    
    const mailtoUrl = `mailto:${email}?subject=${subject}&body=${body}`;
    
    // Direct trigger without opening a new tab
    window.location.href = mailtoUrl;
  };

  const tiers = [
    {
      name: 'Monthly',
      price: '$15',
      period: '/ month',
      description: 'Billed monthly. Cancel anytime.',
      features: [
        'ZAF Core (30+ tools)',
        'ZAF AI (all features)',
        '1 device per user',
        'All future updates',
        'Founder support',
      ],
      cta: 'Start Free Trial',
      highlight: false,
    },
    {
      name: 'Annual',
      price: '$147',
      period: '/ year',
      description: 'Save 18% vs monthly. Most popular.',
      features: [
        'ZAF Core (30+ tools)',
        'ZAF AI (all features)',
        '1 device per user',
        'All future updates',
        'Founder support',
        '14-day money-back',
      ],
      cta: 'Start Free Trial',
      highlight: true,
    },
    {
      name: 'Enterprise',
      price: 'Contact Us',
      period: '',
      description: 'Team licensing. Volume discount.',
      features: [
        'Everything in Annual',
        'Multi-device access',
        'Priority support',
        'Onboarding support',
        'Custom features',
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

  return (
    <section
      ref={sectionRef}
      id="pricing"
      className="relative py-24 lg:py-32 overflow-hidden"
    >
      <div className="absolute inset-0 bg-zaf-navy-darker" />
      
      <div className="relative z-10 w-full section-padding">
        <div className="max-w-6xl mx-auto">
          <div className="pricing-header text-center mb-16">
            <span className="label-mono mb-4 block">PRICING</span>
            <h2 className="heading-lg text-zaf-text mb-4">
              Simple, Transparent{' '}
              <span className="text-gradient-gold">Pricing</span>
            </h2>
            <p className="body-md max-w-xl mx-auto">
              Choose the plan that works best for your financial modeling needs.
            </p>
          </div>

          <div className="pricing-grid grid md:grid-cols-3 gap-8">
            {tiers.map((tier, index) => (
              <div
                key={index}
                className={`pricing-card relative p-8 rounded-2xl border transition-all duration-300 ${
                  tier.highlight
                    ? 'bg-white/[0.05] border-zaf-gold shadow-[0_0_40px_-15px_rgba(212,175,55,0.3)]'
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
                  <h3 className="text-xl font-bold text-zaf-text mb-2">{tier.name}</h3>
                  <div className="flex items-baseline gap-1 mb-2">
                    <span className="text-4xl font-bold text-zaf-text">{tier.price}</span>
                    <span className="text-zaf-text-muted">{tier.period}</span>
                  </div>
                  <p className="text-sm text-zaf-text-muted">{tier.description}</p>
                </div>

                <div className="space-y-4 mb-8">
                  {tier.features.map((feature, fIndex) => (
                    <div key={fIndex} className="flex items-start gap-3">
                      <Check className="w-5 h-5 text-zaf-gold flex-shrink-0 mt-0.5" />
                      <span className="text-sm text-zaf-text-muted">{feature}</span>
                    </div>
                  ))}
                </div>

                {tier.name === 'Enterprise' ? (
                  <button
                    onClick={handleContactSales}
                    className="btn-outline w-full flex items-center justify-center gap-2 py-3 rounded-xl font-semibold border border-zaf-gold text-zaf-gold hover:bg-zaf-gold hover:text-zaf-navy-darker transition-all duration-300"
                  >
                    <Mail className="w-4 h-4" />
                    {tier.cta}
                  </button>
                ) : (
                  <a
                    href="/ZAF_tools_Suite.xlam"
                    download
                    className={`w-full flex items-center justify-center gap-2 py-3 rounded-xl font-semibold transition-all duration-300 ${
                      tier.highlight
                        ? 'bg-zaf-gold text-zaf-navy-darker hover:bg-zaf-gold/90'
                        : 'bg-white/10 text-zaf-text hover:bg-white/20'
                    }`}
                  >
                    <Download className="w-4 h-4" />
                    {tier.cta}
                  </a>
                )}
              </div>
            ))}
          </div>

          <div className="mt-12 text-center">
            <p className="text-sm text-zaf-text-muted italic">
              "Most popular — used by FDD professionals at boutique advisory firms across US, UK, UAE and India."
            </p>
          </div>
        </div>
      </div>
    </section>
  );
};

export default Pricing;
