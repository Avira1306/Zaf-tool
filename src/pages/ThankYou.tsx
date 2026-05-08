import { useEffect } from 'react';
import { Helmet } from 'react-helmet-async';
import { CheckCircle, Mail, Home } from 'lucide-react';
import { Link } from 'react-router-dom';

const ThankYou = () => {
  useEffect(() => {
    window.scrollTo(0, 0);
  }, []);

  return (
    <>
      <Helmet>
        <title>Thank You | ZAF Tools</title>
        <meta name="description" content="Thank you for subscribing to ZAF Tools. Your licence key will be emailed to you shortly." />
      </Helmet>

      <div className="min-h-screen bg-[#1B2A4A] flex items-center justify-center px-4 py-12">
        <div className="max-w-md w-full text-center">
          {/* Success Icon */}
          <div className="mb-8 flex justify-center">
            <CheckCircle className="w-16 h-16 text-[#C9A84C]" />
          </div>

          {/* Heading */}
          <h1 className="text-3xl sm:text-4xl font-bold text-white mb-4">
            Thank you for subscribing to ZAF Tools!
          </h1>

          {/* Main Message */}
          <p className="text-lg text-gray-300 mb-8">
            Your licence key will be emailed to you within a few hours at the email you used during payment.
          </p>

          {/* Support Section */}
          <div className="bg-white/5 border border-white/10 rounded-xl p-6 mb-8">
            <p className="text-gray-300 mb-2">Questions?</p>
            <a
              href="mailto:abhishek.bhandari@zaftool.com"
              className="inline-flex items-center gap-2 text-[#C9A84C] hover:text-[#D4B76A] font-semibold transition-colors"
            >
              <Mail className="w-4 h-4" />
              abhishek.bhandari@zaftool.com
            </a>
          </div>

          {/* Back to Home Link */}
          <Link
            to="/"
            className="inline-flex items-center gap-2 px-6 py-3 bg-[#C9A84C] text-[#1B2A4A] rounded-xl font-semibold hover:bg-[#D4B76A] transition-all duration-300"
          >
            <Home className="w-4 h-4" />
            Back to Home
          </Link>
        </div>
      </div>
    </>
  );
};

export default ThankYou;
