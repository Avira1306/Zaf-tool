import { useEffect, useRef, useState } from 'react';
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { ChevronDown, MessageCircle } from 'lucide-react';

gsap.registerPlugin(ScrollTrigger);

const FAQ = () => {
  const sectionRef = useRef<HTMLElement>(null);
  const [openIndex, setOpenIndex] = useState<number | null>(null);

  const faqs = [
    {
      question: 'Which Excel versions does ZAF Tools support?',
      answer: 'ZAF Tools supports Excel 2016, 2019, 2021, and Microsoft 365 (desktop versions) on Windows. We recommend using the latest version of Excel for the best experience. Mac support is on our roadmap for Q3 2025.',
    },
    {
      question: 'Is my data safe with ZAF Tools?',
      answer: 'Absolutely. ZAF Core operates 100% offline—your data never leaves your computer. ZAF AI features only send the minimal necessary data to our secure servers (e.g., formula text for explanation), and we never store your spreadsheet content. We are SOC 2 Type II compliant.',
    },
    {
      question: 'Does ZAF Tools use VBA macros?',
      answer: 'Yes, ZAF Core uses VBA for maximum compatibility and performance within Excel. ZAF AI features use a combination of VBA and our secure cloud API. All code is digitally signed and scanned for security.',
    },
    {
      question: 'What can ZAF AI actually do?',
      answer: 'ZAF AI can: (1) Build complete financial models from scratch using natural language, (2) Explain any formula in plain English, (3) Answer questions about your spreadsheet via chat, (4) Generate formulas from descriptions, (5) Detect anomalies and potential errors, and (6) Provide financial analysis and insights.',
    },
    {
      question: 'How does the 14-day free trial work?',
      answer: 'Simply download ZAF Tools and start using it immediately—no credit card required. You\'ll have full access to all features for 14 days. At the end of the trial, you can purchase a license to continue using the product.',
    },
    {
      question: 'What\'s your refund policy?',
      answer: 'We offer a 14-day money-back guarantee on all purchases. If you\'re not satisfied with ZAF Tools for any reason, simply email us within 14 days of purchase for a full refund—no questions asked.',
    },
    {
      question: 'Can I use ZAF Tools on multiple devices?',
      answer: 'Each license allows installation on 1 device. Contact us at Abhishek.bhandari@zaftool.com if you need multi-device access.',
    },
    {
      question: 'How do I get support if I need help?',
      answer: 'All users get access to our documentation and video tutorials. Paid users receive direct email support with 24-hour response time. Enterprise customers get priority support with a dedicated account manager and WhatsApp access.',
    },
  ];

  useEffect(() => {
    const ctx = gsap.context(() => {
      // Header animation
      gsap.fromTo(
        '.faq-header',
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

      // FAQ items stagger
      gsap.fromTo(
        '.faq-item',
        { y: 20, opacity: 0 },
        {
          y: 0,
          opacity: 1,
          duration: 0.4,
          stagger: 0.06,
          scrollTrigger: {
            trigger: '.faq-list',
            start: 'top 80%',
            toggleActions: 'play none none reverse',
          },
        }
      );
    }, sectionRef);

    return () => ctx.revert();
  }, []);

  const toggleFAQ = (index: number) => {
    setOpenIndex(openIndex === index ? null : index);
  };

  return (
    <section
      ref={sectionRef}
      id="faq"
      className="relative py-24 lg:py-32 overflow-hidden"
    >
      {/* Background */}
      <div className="absolute inset-0 bg-zaf-navy-darker" />

      <div className="relative z-10 w-full section-padding">
        <div className="max-w-3xl mx-auto">
          {/* Section Header */}
          <div className="faq-header text-center mb-12">
            <span className="label-mono mb-4 block">FAQ</span>
            <h2 className="heading-lg text-zaf-text mb-4">
              Frequently Asked{' '}
              <span className="text-gradient-gold">Questions</span>
            </h2>
            <p className="body-md">
              Everything you need to know about ZAF Tools. Can&apos;t find what you&apos;re looking for? Reach out to us.
            </p>
          </div>

          {/* FAQ List */}
          <div className="faq-list">
            {faqs.map((faq, index) => (
              <div
                key={index}
                className="faq-item border-b border-white/10 last:border-b-0"
              >
                <button
                  onClick={() => toggleFAQ(index)}
                  className="w-full py-5 flex items-center justify-between text-left group"
                >
                  <span className={`text-base font-medium transition-colors duration-200 ${
                    openIndex === index ? 'text-zaf-gold' : 'text-zaf-text group-hover:text-zaf-gold'
                  }`}>
                    {faq.question}
                  </span>
                  <ChevronDown 
                    className={`w-5 h-5 flex-shrink-0 ml-4 transition-transform duration-300 ${
                      openIndex === index ? 'rotate-180 text-zaf-gold' : 'text-zaf-text-muted'
                    }`}
                  />
                </button>
                <div 
                  className={`overflow-hidden transition-all duration-300 ${
                    openIndex === index ? 'max-h-96 pb-5' : 'max-h-0'
                  }`}
                >
                  <p className="text-sm text-zaf-text-muted leading-relaxed">
                    {faq.answer}
                  </p>
                </div>
              </div>
            ))}
          </div>

          {/* Contact CTA */}
          <div className="mt-12 text-center">
            <div className="inline-flex items-center gap-3 px-6 py-4 rounded-2xl bg-white/[0.03] border border-white/10">
              <div className="w-10 h-10 rounded-full bg-zaf-gold/10 flex items-center justify-center">
                <MessageCircle className="w-5 h-5 text-zaf-gold" />
              </div>
              <div className="text-left">
                <p className="text-sm font-medium text-zaf-text">Still have questions?</p>
                <a 
                  href="mailto:Abhishek.bhandari@zaftool.com?subject=Support Inquiry for ZAF Tools"
                  className="text-sm text-zaf-gold hover:underline font-semibold"
                >
                  Contact our team
                </a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default FAQ;
