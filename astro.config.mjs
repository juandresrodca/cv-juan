import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';
import react from '@astrojs/react';

export default defineConfig({
  integrations: [tailwind(), react()],
  site: 'https://juandresrodca.github.io',
  base: '/cv-juan', 
  output: 'static',
  build: {
    assets: '_astro'
  },
  trailingSlash: 'always'
});
