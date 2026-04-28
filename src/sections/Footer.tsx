import { useEffect, useRef } from 'react';
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { Mail, MessageCircle, Linkedin, Twitter, Github } from 'lucide-react';

gsap.registerPlugin(ScrollTrigger);

const Footer = () => {
  const sectionRef = useRef<HTMLElement>(null);

  const productLinks = [
    { label: 'Features', href: '#features' },
    { label: 'Pricing', href: '#pricing' },
    { label: 'Changelog', href: '#' },
    { label: 'Roadmap', href: '#' },
  ];

  const scrollToSection = (href: string) => {
    if (href === '#') return;
    const element = document.querySelector(href);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
  };

  useEffect(() => {
    const ctx = gsap.context(() => {
      gsap.fromTo(
        '.footer-content',
        { y: 30, opacity: 0 },
        {
          y: 0,
          opacity: 1,
          duration: 0.6,
          scrollTrigger: {
            trigger: sectionRef.current,
            start: 'top 90%',
            toggleActions: 'play none none reverse',
          },
        }
      );
    }, sectionRef);

    return () => ctx.revert();
  }, []);

  return (
    <footer
      ref={sectionRef}
      id="contact"
      className="relative pt-20 pb-8 overflow-hidden"
    >
      {/* Background */}
      <div className="absolute inset-0 bg-zaf-navy-darker" />
      
      {/* Top border */}
      <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-white/10 to-transparent" />

      <div className="relative z-10 w-full section-padding">
        <div className="footer-content max-w-7xl mx-auto">
          {/* Main Footer Content */}
          <div className="grid sm:grid-cols-2 lg:grid-cols-5 gap-12 mb-16">
            {/* Brand Column */}
            <div className="lg:col-span-2">
              <a href="#" className="flex items-center gap-3 mb-6">
                <picture>
                  <source srcSet="/logo.webp" type="image/webp" />
                  <img 
                    src="/logo.png" 
                    alt="ZAF Tools" 
                    className="h-12 w-auto"
                  />
                </picture>
              </a>
              <p className="text-sm text-zaf-text-muted mb-6 max-w-sm leading-relaxed">
                The Excel add-in built for finance professionals. 
                30+ tools + AI that builds your financial models.
              </p>
              
              {/* Contact Info */}
              <div className="space-y-3">
                <a 
                  href="mailto:Abhishek.bhandari@zaftool.com"
                  className="flex items-center gap-3 text-sm text-zaf-text-muted hover:text-zaf-gold transition-colors"
                >
                  <Mail className="w-4 h-4" />
                  Abhishek.bhandari@zaftool.com
                </a>
                <a 
                  href="https://wa.me/919999999999"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-3 text-sm text-zaf-text-muted hover:text-zaf-gold transition-colors"
                >
                  <MessageCircle className="w-4 h-4" />
                  
                </a>
              </div>

              {/* Social Links */}
              <div className="flex items-center gap-3 mt-6">
                <a 
                  href="#" 
                  className="w-10 h-10 rounded-lg bg-white/[0.05] flex items-center justify-center text-zaf-text-muted hover:text-zaf-gold hover:bg-white/[0.1] transition-all"
                  aria-label="LinkedIn"
                >
                  <Linkedin className="w-4 h-4" />
                </a>
                <a 
                  href="#" 
                  className="w-10 h-10 rounded-lg bg-white/[0.05] flex items-center justify-center text-zaf-text-muted hover:text-zaf-gold hover:bg-white/[0.1] transition-all"
                  aria-label="Twitter"
                >
                  <Twitter className="w-4 h-4" />
                </a>
                <a 
                  href="#" 
                  className="w-10 h-10 rounded-lg bg-white/[0.05] flex items-center justify-center text-zaf-text-muted hover:text-zaf-gold hover:bg-white/[0.1] transition-all"
                  aria-label="GitHub"
                >
                  <Github className="w-4 h-4" />
                </a>
              </div>
            </div>

            {/* Product Links */}
            <div>
              <h4 className="text-sm font-semibold text-zaf-text mb-4">Product</h4>
              <ul className="space-y-3">
                {productLinks.map((link, index) => (
                  <li key={index}>
                    <button
                      onClick={() => scrollToSection(link.href)}
                      className="text-sm text-zaf-text-muted hover:text-zaf-gold transition-colors"
                    >
                      {link.label}
                    </button>
                  </li>
                ))}
              </ul>
            </div>

            {/* Contact */}
            <div>
              <h4 className="text-sm font-semibold text-zaf-text mb-4">Contact</h4>
              <ul className="space-y-3">
                <li><a href="mailto:Abhishek.bhandari@zaftool.com" className="text-sm text-zaf-text-muted hover:text-zaf-gold transition-colors">Abhishek.bhandari@zaftool.com</a></li>
                <li><a href="https://linkedin.com/in/abhishek-bhandari" target="_blank" rel="noopener noreferrer" className="text-sm text-zaf-text-muted hover:text-zaf-gold transition-colors">LinkedIn</a></li>
              </ul>
            </div>
          </div>

          {/* Office Locations - Hidden */}
          <div className="hidden">
            <div className="flex items-center gap-2 text-sm text-zaf-text-muted">
              <div className="w-2 h-2 rounded-full bg-emerald-400" />
              New York
            </div>
            <div className="flex items-center gap-2 text-sm text-zaf-text-muted">
              <div className="w-2 h-2 rounded-full bg-emerald-400" />
              London
            </div>
            <div className="flex items-center gap-2 text-sm text-zaf-text-muted">
              <div className="w-2 h-2 rounded-full bg-emerald-400" />
              Remote
            </div>
          </div>

          {/* Bottom Bar */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
            <p className="text-xs text-zaf-text-muted">
              © {new Date().getFullYear()} ZAF Tools. All rights reserved.
            </p>
            <p className="text-xs text-zaf-text-muted">
              Built by finance professionals, for the world.
            </p>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
