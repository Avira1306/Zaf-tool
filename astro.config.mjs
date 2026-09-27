import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';

export default defineConfig({
  site: 'https://www.zaftool.com',
  trailingSlash: 'never',
  build: { format: 'file' },
  integrations: [sitemap({
    filter: (page) => !page.includes('/thank-you') && !page.includes('/404'),
    changefreq: 'weekly',
  })],
});
