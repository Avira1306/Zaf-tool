import { useParams } from 'react-router-dom';
import { Helmet } from 'react-helmet-async';
import { posts } from '../../data/posts';
import Navigation from '../../sections/Navigation';
import Footer from '../../sections/Footer';

const BlogPost = () => {
  const { slug } = useParams();
  const post = posts.find((p) => p.slug === slug);

  if (!post) {
    return (
      <div className="min-h-screen bg-zaf-navy-darker flex items-center justify-center">
        <h1 className="text-zaf-text text-2xl">Post not found</h1>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-zaf-navy-darker">
      <Helmet>
        <title>{post.title} | ZAF Tools Blog</title>
        <meta name="description" content={post.excerpt} />
        <link rel="canonical" href={`https://www.zaftool.com/blog/${post.slug}`} />
        
        {/* Open Graph */}
        <meta property="og:type" content="article" />
        <meta property="og:title" content={post.title} />
        <meta property="og:description" content={post.excerpt} />
        <meta property="og:url" content={`https://www.zaftool.com/blog/${post.slug}`} />
        <meta property="og:image" content="https://www.zaftool.com/og-image.jpg" />
      </Helmet>

      <Navigation />

      <main className="pt-32 pb-24 section-padding">
        <article className="max-w-3xl mx-auto">
          <div className="mb-12">
            <a href="/blog" className="text-zaf-gold text-sm font-medium mb-8 inline-block hover:underline">
              ← Back to Blog
            </a>
            <h1 className="text-4xl md:text-5xl font-bold text-zaf-text mb-6 leading-tight">
              {post.title}
            </h1>
            <div className="flex items-center gap-4 text-zaf-text-muted text-sm">
              <span>{post.date}</span>
              <span>•</span>
              <span>{post.author}</span>
            </div>
          </div>

          <div 
            className="prose prose-invert prose-gold max-w-none"
            dangerouslySetInnerHTML={{ __html: post.content }}
          />
        </article>
      </main>

      <Footer />
    </div>
  );
};

export default BlogPost;
