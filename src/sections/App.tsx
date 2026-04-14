import { useEffect, useRef, useState } from 'react';
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
import './App.css';

gsap.registerPlugin(ScrollTrigger);

function App() {
  const [isLoaded, setIsLoaded] = useState(false);
  const mainRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Page load animation
    const timer = setTimeout(() => {
      setIsLoaded(true);
    }, 100);

    return () => clearTimeout(timer);
  }, []);

  useEffect(() => {
    if (!isLoaded) return;

    // Initialize scroll animations
    const ctx = gsap.context(() => {
      // Refresh ScrollTrigger after all components mount
      ScrollTrigger.refresh();
    }, mainRef);

    return () => ctx.revert();
  }, [isLoaded]);

  return (
    <div 
      ref={mainRef}
      className={`min-h-screen bg-zaf-navy-darker transition-opacity duration-500 ${isLoaded ? 'opacity-100' : 'opacity-0'}`}
    >
      {/* Grain Overlay */}
      <div className="grain-overlay" />
      
      {/* Navigation */}
      <Navigation />
      
      {/* Main Content */}
      <main className="relative">
        {/* Section 1: Hero */}
        <Hero />
        
        {/* Section 2: Problem */}
        <Problem />
        
        {/* Section 3: Solution */}
        <Solution />
        
        {/* Section 4: Video Demo */}
        <VideoDemo />

        {/* Section 5: Flagship Feature */}
        <FlagshipFeature />
        
        {/* Section 5: Use Cases */}
        <UseCases />
        
        {/* Section 6: Pricing */}
        <Pricing />
        
        {/* Section 7: FAQ */}
        <FAQ />
        
        {/* Section 8: Footer */}
        <Footer />
      </main>
    </div>
  );
}

export default App;
