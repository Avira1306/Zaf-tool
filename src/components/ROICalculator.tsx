import { useState } from 'react';
import { DollarSign, Clock, TrendingUp, Zap } from 'lucide-react';

const ROICalculator = () => {
  const [manualHours, setManualHours] = useState(40);
  const [hourlyRate, setHourlyRate] = useState(50);
  const [reductionPercentage, setReductionPercentage] = useState(90);

  const monthlySavingsHours = manualHours * (reductionPercentage / 100);
  const monthlySavingsDollars = monthlySavingsHours * hourlyRate;
  const annualSavingsDollars = monthlySavingsDollars * 12;

  return (
    <section id="roi-calculator" className="section-padding bg-zaf-navy-darker">
      <div className="max-w-4xl mx-auto text-center">
        <h2 className="heading-lg text-zaf-text mb-4">
          Calculate Your <span className="text-gradient-gold">ROI</span> with ZAF Tools
        </h2>
        <p className="body-lg text-zaf-text-muted mb-12">
          See how much time and money you can save by automating your financial modeling with AI.
        </p>

        <div className="bg-zaf-navy rounded-2xl p-6 md:p-10 shadow-xl border border-white/10">
          <div className="grid md:grid-cols-3 gap-8 mb-10">
            {/* Input: Manual Hours */}
            <div className="flex flex-col items-center">
              <label htmlFor="manualHours" className="text-sm font-medium text-zaf-text-muted mb-2">
                Manual Hours / Month
              </label>
              <input
                type="number"
                id="manualHours"
                value={manualHours}
                onChange={(e) => setManualHours(Number(e.target.value))}
                className="input-zaf w-full text-center"
                min="0"
                max="160"
              />
              <p className="text-xs text-zaf-text-muted mt-2">Hours spent on repetitive tasks.</p>
            </div>

            {/* Input: Hourly Rate */}
            <div className="flex flex-col items-center">
              <label htmlFor="hourlyRate" className="text-sm font-medium text-zaf-text-muted mb-2">
                Average Hourly Rate ($)
              </label>
              <input
                type="number"
                id="hourlyRate"
                value={hourlyRate}
                onChange={(e) => setHourlyRate(Number(e.target.value))}
                className="input-zaf w-full text-center"
                min="0"
                max="500"
              />
              <p className="text-xs text-zaf-text-muted mt-2">Your or your team's average cost.</p>
            </div>

            {/* Input: Reduction Percentage */}
            <div className="flex flex-col items-center">
              <label htmlFor="reductionPercentage" className="text-sm font-medium text-zaf-text-muted mb-2">
                Time Reduction with ZAF Tools (%)
              </label>
              <input
                type="range"
                id="reductionPercentage"
                value={reductionPercentage}
                onChange={(e) => setReductionPercentage(Number(e.target.value))}
                className="w-full accent-zaf-gold"
                min="0"
                max="100"
              />
              <p className="text-xs text-zaf-text-muted mt-2">{reductionPercentage}% estimated automation.</p>
            </div>
          </div>

          {/* Results */}
          <div className="grid md:grid-cols-3 gap-6 mt-8 border-t border-white/10 pt-8">
            <div className="flex flex-col items-center">
              <Clock className="w-8 h-8 text-zaf-gold mb-3" />
              <p className="text-lg font-semibold text-zaf-text">
                {monthlySavingsHours.toFixed(0)} Hours
              </p>
              <p className="text-sm text-zaf-text-muted">Saved Monthly</p>
            </div>
            <div className="flex flex-col items-center">
              <DollarSign className="w-8 h-8 text-zaf-gold mb-3" />
              <p className="text-lg font-semibold text-zaf-text">
                ${monthlySavingsDollars.toFixed(0)}
              </p>
              <p className="text-sm text-zaf-text-muted">Saved Monthly</p>
            </div>
            <div className="flex flex-col items-center">
              <TrendingUp className="w-8 h-8 text-zaf-gold mb-3" />
              <p className="text-lg font-semibold text-zaf-text">
                ${annualSavingsDollars.toFixed(0)}
              </p>
              <p className="text-sm text-zaf-text-muted">Saved Annually</p>
            </div>
          </div>

          {/* CTA */}
          <div className="mt-12">
            <a href="/download" className="btn-gold text-lg flex items-center justify-center gap-2 mx-auto max-w-xs">
              <Zap className="w-5 h-5" />
              Start Your Free Trial
            </a>
            <p className="text-xs text-zaf-text-muted mt-4">No credit card required. Instant download.</p>
          </div>
        </div>
      </div>
    </section>
  );
};

export default ROICalculator;
