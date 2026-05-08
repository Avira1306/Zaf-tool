import { useState } from 'react';
import { Loader2 } from 'lucide-react';

interface BuyNowButtonProps {
  planKey: string;
}

const WORKER_URL = 'https://zaf-razorpay-worker.zionadvisor-ai.workers.dev';

const BuyNowButton = ({ planKey }: BuyNowButtonProps) => {
  const [isLoading, setIsLoading] = useState(false);

  const handleBuyNow = async () => {
    setIsLoading(true);
    try {
      const res = await fetch(WORKER_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ planKey })
      });
      const data = await res.json();
      if (data.url) {
        window.location.href = data.url;
      } else {
        alert('Something went wrong. Please try again.');
        setIsLoading(false);
      }
    } catch (e) {
      alert('Network error. Please try again.');
      setIsLoading(false);
    }
  };

  return (
    <button
      onClick={handleBuyNow}
      disabled={isLoading}
      className="w-full flex items-center justify-center gap-2 py-3 rounded-xl font-semibold transition-all duration-300 bg-[#C9A84C] text-[#1B2A4A] hover:bg-[#D4B76A] disabled:opacity-75 disabled:cursor-not-allowed"
    >
      {isLoading ? (
        <>
          <Loader2 className="w-4 h-4 animate-spin" />
          Loading...
        </>
      ) : (
        'Buy Now'
      )}
    </button>
  );
};

export default BuyNowButton;
