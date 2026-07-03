import { useState, useEffect } from 'react';
import { Menu, X, Download } from 'lucide-react';
import { Link, useLocation, useNavigate } from 'react-router-dom';

const Navigation = () => {
  const [isScrolled, setIsScrolled] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 50);
    };

    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const navLinks = [
    { label: 'Features', href: '/#features' },
    { label: 'Solutions', href: '/#solutions' },
    { label: 'Pricing', href: '/#pricing' },
    { label: 'What\'s New', href: '/changelog' },
    { label: 'Blog', href: '/blog' },
    { label: 'Resources', href: '/#faq' },
    { label: 'Contact', href: '/#contact' },
  ];

  const handleNavClick = (href: string) => {
    setIsMobileMenuOpen(false);
    
    if (href.startsWith('/#')) {
      const targetId = href.replace('/#', '');
      if (location.pathname === '/') {
        // Already on homepage, just scroll
        const element = document.getElementById(targetId);
        if (element) {
          element.scrollIntoView({ behavior: 'smooth' });
        }
      } else {
        // On another page, navigate to homepage with hash
        navigate(href);
      }
    } else {
      // Regular route navigation
      navigate(href);
    }
  };

  return (
    <>
      <nav
        className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
          isScrolled ? 'nav-blur py-3' : 'bg-transparent py-5'
        }`}
      >
        <div className="w-full section-padding">
          <div className="flex items-center justify-between">
            {/* Logo */}
            <Link 
              to="/" 
              className="flex items-center gap-3 group"
              onClick={() => {
                if (location.pathname === '/') {
                  window.scrollTo({ top: 0, behavior: 'smooth' });
                }
              }}
            >
              <picture>
                <source srcSet="/logo.webp" type="image/webp" />
                <img 
                  src="/logo.png" 
                  alt="ZAF Tools" 
                  className="h-8 w-auto rounded-sm"
                />
              </picture>
              <span className="hidden sm:block text-lg font-semibold text-zaf-text">
                ZAF Tools <span className="text-zaf-gold">AI Suite</span>
              </span>
            </Link>

            {/* Desktop Navigation */}
            <div className="hidden lg:flex items-center gap-8">
              {navLinks.map((link) => (
                <button
                  key={link.label}
                  onClick={() => handleNavClick(link.href)}
                  className="text-sm font-medium text-zaf-text-muted hover:text-zaf-text transition-colors duration-200"
                >
                  {link.label}
                </button>
              ))}
            </div>

            {/* CTA Button */}
            <div className="flex items-center gap-4">
              <button 
                onClick={() => handleNavClick('/#pricing')}
                className="hidden sm:flex btn-primary items-center gap-2 text-sm"
              >
                <Download className="w-4 h-4" />
                Start Free Trial
              </button>

              {/* Mobile Menu Button */}
              <button
                onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
                className="lg:hidden p-2 text-zaf-text hover:text-zaf-gold transition-colors"
                aria-label="Toggle menu"
              >
                {isMobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
              </button>
            </div>
          </div>
        </div>
      </nav>

      {/* Mobile Menu */}
      <div
        className={`fixed inset-0 z-40 lg:hidden transition-all duration-300 ${
          isMobileMenuOpen ? 'opacity-100 pointer-events-auto' : 'opacity-0 pointer-events-none'
        }`}
      >
        <div 
          className="absolute inset-0 bg-black/60 backdrop-blur-sm"
          onClick={() => setIsMobileMenuOpen(false)}
        />
        <div
          className={`absolute top-0 right-0 w-full max-w-sm h-full bg-zaf-navy-darker border-l border-white/10 transition-transform duration-300 ${
            isMobileMenuOpen ? 'translate-x-0' : 'translate-x-full'
          }`}
        >
          <div className="p-6 pt-20">
            <div className="flex flex-col gap-4">
              {navLinks.map((link) => (
                <button
                  key={link.label}
                  onClick={() => handleNavClick(link.href)}
                  className="text-left text-lg font-medium text-zaf-text-muted hover:text-zaf-text transition-colors py-3 border-b border-white/5"
                >
                  {link.label}
                </button>
              ))}
              <button 
                onClick={() => handleNavClick('/#pricing')}
                className="btn-gold mt-4 flex items-center justify-center gap-2"
              >
                <Download className="w-5 h-5" />
                Start Free Trial
              </button>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default Navigation;
