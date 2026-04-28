import { Helmet } from 'react-helmet-async';
import { posts } from '../../data/posts';
import Navigation from '../../sections/Navigation';
import Footer from '../../sections/Footer';

const BlogIndex = () => {
  return (
    <div className="min-h-screen bg-zaf-navy-darker">
      <Helmet>
        <title>ZAF Tools Blog | Excel AI & Financial Modeling Insights</title>
        <meta name="description" content="Expert insights on financial due diligence, M&A modeling, and Excel AI tools. Learn how to build better models faster." />
        <link rel="canonical" href="https://www.zaftool.com/blog" />
      </Helmet>
      
      <Navigation />
      
      <main className="pt-32 pb-24 section-padding">
        <div className="max-w-4xl mx-auto">
          <div className="mb-16 text-center">
            <span className="label-mono mb-4 block">RESOURCES</span>
            <h1 className="heading-lg text-zaf-text mb-4">
              Financial Modeling <span className="text-gradient-gold">Insights</span>
            </h1>
            <p className="body-md">
              Expert guides and articles for FDD and M&A professionals.
            </p>
          </div>

          <div className="grid gap-8">
            {posts.map((post) => (
              <a 
                key={post.slug}
                href={`/blog/${post.slug}`}
                className="group p-8 rounded-2xl bg-white/[0.02] border border-white/10 hover:border-zaf-gold/30 transition-all duration-300"
              >
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
                  <h2 className="text-2xl font-bold text-zaf-text group-hover:text-zaf-gold transition-colors">
                    {post.title}
                  </h2>
                  <span className="text-sm text-zaf-text-muted whitespace-nowrap">
                    {post.date}
                  </span>
                </div>
                <p className="text-zaf-text-muted mb-6">
                  {post.excerpt}
                </p>
                <span className="text-zaf-gold font-medium inline-flex items-center gap-2">
                  Read Article 
                  <span className="group-hover:translate-x-1 transition-transform">→</span>
                </span>
              </a>
            ))}
          </div>
        </div>
      </main>

      <Footer />
    </div>
  );
};

export default BlogIndex;
