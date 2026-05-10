import { useEffect, useRef, useState } from 'react';
import { Helmet } from 'react-helmet-async';
import { BrowserRouter as Router, Routes, Route, useLocation } from 'react-router-dom';
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import Navigation from './sections/Navigation';
import Hero from './sections/Hero';
import Problem from './sections/Problem';
import Solution from './sections/Solution';
import FlagshipFeature from './sections/FlagshipFeature';
import VideoDemo from './sections/VideoDemo';
import UseCases from './sections/UseCases';
import Pricing from './sections/Pricing';
import FAQ from './sections/FAQ';
import Footer from './sections/Footer';
import BlogIndex from './pages/Blog/index';
import BlogPost from './pages/Blog/BlogPost';
import ThankYou from './pages/ThankYou';
import Changelog from './pages/Changelog';
import ROICalculator from './components/ROICalculator';
import './App.css';

gsap.registerPlugin(ScrollTrigger);

// ScrollToTop component to handle scroll reset on route change
function ScrollToTop() {
  const { pathname, hash } = useLocation();
  
  useEffect(() => {
    if (!hash) {
      window.scrollTo(0, 0);
    } else {
      const id = hash.replace('#', '');
      const element = document.getElementById(id);
      if (element) {
        element.scrollIntoView({ behavior: 'smooth' });
      }
    }
  }, [pathname, hash]);
  
  return null;
}

function MainSite() {
  const [isLoaded, setIsLoaded] = useState(false);
  const mainRef = useRef<HTMLDivElement>(null);
  const location = useLocation();

  useEffect(() => {
    const timer = setTimeout(() => {
      setIsLoaded(true);
    }, 100);
    return () => clearTimeout(timer);
  }, []);

  useEffect(() => {
    if (!isLoaded) return;
    
    // Refresh ScrollTrigger when entering the main site
    const ctx = gsap.context(() => {
      ScrollTrigger.refresh();
    }, mainRef);
    
    return () => {
      ctx.revert();
      // Kill all ScrollTriggers when leaving the main site to prevent memory leaks and freezes
      ScrollTrigger.getAll().forEach(t => t.kill());
    };
  }, [isLoaded, location.pathname]);

  return (
    <div 
      ref={mainRef}
      className={`min-h-screen bg-zaf-navy-darker transition-opacity duration-500 ${isLoaded ? 'opacity-100' : 'opacity-0'}`}
    >
      <Helmet>
        <title>ZAF Tools AI Suite | Excel Add-In + AI for FDD & Financial Modeling</title>
        <meta name="description" content="30+ Excel tools + AI built for financial due diligence, M&A advisors & CA firms. Quality of Earnings, model audit, anomaly detection & EBITDA bridge — one-click inside Excel. $15/month. 14-day free trial." />
        <link rel="canonical" href="https://www.zaftool.com/" />
        
        {/* Open Graph */}
        <meta property="og:type" content="website" />
        <meta property="og:title" content="ZAF Tools AI Suite | Excel Add-In + AI for FDD & Financial Modeling" />
        <meta property="og:description" content="30+ Excel tools + AI for financial due diligence & M&A. Quality of Earnings, model audit, anomaly detection — one-click inside Excel. $15/month." />
        <meta property="og:url" content="https://www.zaftool.com/" />
        <meta property="og:image" content="https://www.zaftool.com/og-image.jpg" />
        <meta property="og:image:width" content="1200" />
        <meta property="og:image:height" content="630" />
        <meta property="og:site_name" content="ZAF Tools" />

        {/* Twitter Card */}
        <meta name="twitter:card" content="summary_large_image" />
        <meta name="twitter:title" content="ZAF Tools AI Suite | Excel Add-In + AI for FDD & Financial Modeling" />
        <meta name="twitter:description" content="30+ Excel tools + AI for FDD & M&A. $15/month." />
        <meta name="twitter:image" content="https://www.zaftool.com/og-image.jpg" />

        {/* SoftwareApplication Schema */}
        <script type="application/ld+json">
          {JSON.stringify({
            "@context": "https://schema.org",
            "@graph": [
              {
                "@type": "SoftwareApplication",
                "name": "ZAF Tools AI Suite",
                "applicationCategory": "BusinessApplication",
                "operatingSystem": "Windows",
                "offers": [
                  {
                    "@type": "Offer",
                    "name": "Monthly",
                    "price": "15.00",
                    "priceCurrency": "USD",
                    "billingIncrement": "P1M"
                  },
                  {
                    "@type": "Offer",
                    "name": "Annual",
                    "price": "147.00",
                    "priceCurrency": "USD",
                    "billingIncrement": "P1Y"
                  }
                ],
                "description": "Excel add-in with 30+ professional tools and AI for financial due diligence and M&A professionals. BYOK model — works with OpenAI, Claude, Gemini, and more.",
                "url": "https://www.zaftool.com",
                "image": "https://www.zaftool.com/og-image.jpg",
                "author": {
                  "@type": "Person",
                  "name": "Abhishek Bhandari",
                  "url": "https://www.linkedin.com/in/abhishek-bhandari-6b048979/"
                }
              },
              {
                "@type": "Organization",
                "name": "ZAF Tools",
                "url": "https://www.zaftool.com",
                "logo": "https://www.zaftool.com/logo.png",
                "sameAs": [
                  "https://www.linkedin.com/in/abhishek-bhandari-6b048979/"
                ]
              }
            ]
          })}
        </script>

        {/* FAQPage Schema */}
        <script type="application/ld+json">
          {JSON.stringify({
            "@context": "https://schema.org",
            "@type": "FAQPage",
            "mainEntity": [
              {
                "@type": "Question",
                "name": "Which Excel versions does ZAF Tools support?",
                "acceptedAnswer": {
                  "@type": "Answer",
                  "text": "ZAF Tools supports Excel 2016, 2019, 2021, and Microsoft 365 desktop on Windows. Mac is not currently supported."
                }
              },
              {
                "@type": "Question",
                "name": "Is my financial data safe with ZAF Tools?",
                "acceptedAnswer": {
                  "@type": "Answer",
                  "text": "Yes. ZAF Tools uses a BYOK (bring your own key) model — your data is sent only to the AI provider whose API key you supply. Anthropic, OpenAI, and Google all have enterprise-grade data protection. ZAF Tools itself never stores your financial data."
                }
              },
              {
                "@type": "Question",
                "name": "What AI providers does ZAF Tools support?",
                "acceptedAnswer": {
                  "@type": "Answer",
                  "text": "ZAF Tools supports OpenAI, Anthropic Claude, Google Gemini, Kimi, Groq, and OpenRouter. You bring your own API key for whichever provider you prefer."
                }
              },
              {
                "@type": "Question",
                "name": "How does the free trial work?",
                "acceptedAnswer": {
                  "@type": "Answer",
                  "text": "Download the XLAM file and register via the Google Form. You get 14 days of full access to all ZAF Tools AI and Classic features with no credit card required."
                }
              },
              {
                "@type": "Question",
                "name": "What is the difference between ZAF Tools AI and ZAF Tools Classic?",
                "acceptedAnswer": {
                  "@type": "Answer",
                  "text": "ZAF Tools Classic contains 25+ Excel productivity tools for formatting, model audit, consolidation, and navigation. ZAF Tools AI adds a multi-provider AI engine for one-click Quality of Earnings, anomaly detection, EBITDA bridge, LBO analysis, and more. Both modules are included in a single $147/year or $15/month subscription."
                }
              }
            ]
          })}
        </script>
      </Helmet>
      <div className="grain-overlay" />
      <Navigation />
      <main className="relative">
        <Hero />
        <Problem />
        <Solution />
        <VideoDemo />
        <FlagshipFeature />
        <UseCases />
        <ROICalculator />
        <Pricing />
        <FAQ />
        <Footer />
      </main>
    </div>
  );
}

function App() {
  return (
    <Router>
      <ScrollToTop />
      <Routes>
        <Route path="/" element={<MainSite />} />
        <Route path="/blog" element={<BlogIndex />} />
        <Route path="/blog/:slug" element={<BlogPost />} />
        <Route path="/changelog" element={<Changelog />} />
        <Route path="/thank-you" element={<ThankYou />} />
        {/* Fallback for other routes mentioned in brief to homepage for now */}
        <Route path="/features" element={<MainSite />} />
        <Route path="/pricing" element={<MainSite />} />
        <Route path="/solutions" element={<MainSite />} />
        <Route path="/download" element={<MainSite />} />
        <Route path="/contact" element={<MainSite />} />
      </Routes>
    </Router>
  );
}

export default App;
