import { useEffect, useRef } from 'react';
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { Play } from 'lucide-react';

gsap.registerPlugin(ScrollTrigger);

const VideoDemo = () => {
  const sectionRef = useRef<HTMLElement>(null);

  useEffect(() => {
    const ctx = gsap.context(() => {
      gsap.fromTo(
        '.video-header',
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
        '.video-container',
        { scale: 0.95, opacity: 0 },
        {
          scale: 1,
          opacity: 1,
          duration: 0.7,
          scrollTrigger: {
            trigger: '.video-container',
            start: 'top 75%',
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
      id="demo"
      className="relative py-24 lg:py-32 overflow-hidden"
    >
      {/* Background */}
      <div className="absolute inset-0 bg-zaf-navy-darker" />

      {/* Subtle glow */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[400px] bg-zaf-gold/5 rounded-full blur-3xl" />

      <div className="relative z-10 w-full section-padding">
        <div className="max-w-5xl mx-auto">

          {/* Header */}
          <div className="video-header text-center mb-12">
            <span className="label-mono mb-4 block">SEE IT IN ACTION</span>
            <h2 className="heading-lg text-zaf-text mb-4">
              Watch ZAF Tools{' '}
              <span className="text-gradient-gold">Work Live</span>
            </h2>
            <p className="body-md max-w-2xl mx-auto">
              See how finance professionals use ZAF Tools to cut analysis time from hours to minutes — directly inside Excel.
            </p>
          </div>

          {/* Video Container */}
          <div className="video-container gradient-border p-1">
            <div className="relative bg-zaf-navy-dark/80 rounded-2xl overflow-hidden">
              {/* Gold top bar */}
              <div className="flex items-center gap-2 px-4 py-3 border-b border-white/10 bg-zaf-navy-dark/60">
                <div className="flex gap-1.5">
                  <div className="w-3 h-3 rounded-full bg-rose-500/70" />
                  <div className="w-3 h-3 rounded-full bg-amber-500/70" />
                  <div className="w-3 h-3 rounded-full bg-emerald-500/70" />
                </div>
                <div className="flex items-center gap-2 ml-2">
                  <Play className="w-3.5 h-3.5 text-zaf-gold" />
                  <span className="text-xs text-zaf-text-muted font-mono">ZAF Tools — Product Demo</span>
                </div>
              </div>

              {/* YouTube Embed */}
              <div className="relative w-full" style={{ paddingBottom: '56.25%' }}>
                <iframe
                  className="absolute inset-0 w-full h-full"
                  src="https://www.youtube.com/embed/owrcPHFUsq0?si=hN3TMqL43geHzIh_"
                  title="ZAF Tools Product Demo"
                  frameBorder="0"
                  allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share"
                  referrerPolicy="strict-origin-when-cross-origin"
                  allowFullScreen
                />
              </div>
            </div>
          </div>

          {/* Bottom stats */}
          <div className="mt-10 grid grid-cols-3 gap-4 text-center">
            <div>
              <div className="text-2xl font-bold text-zaf-gold mb-1">25+</div>
              <div className="text-xs text-zaf-text-muted">Tools Demonstrated</div>
            </div>
            <div>
              <div className="text-2xl font-bold text-zaf-gold mb-1">3 min</div>
              <div className="text-xs text-zaf-text-muted">To See Full Value</div>
            </div>
            <div>
              <div className="text-2xl font-bold text-zaf-gold mb-1">$149</div>
              <div className="text-xs text-zaf-text-muted">Per Year, All Included</div>
            </div>
          </div>

        </div>
      </div>
    </section>
  );
};

export default VideoDemo;
