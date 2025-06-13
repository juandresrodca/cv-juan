import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';
import react from '@astrojs/react';

export default defineConfig({
  integrations: [tailwind(), react()],
  site: 'https://yourusername.github.io', // Confirm this is correct (e.g., https://juandresrodca.github.io)
  base: '/cv-juan', // Confirm this matches your repo name
  output: 'static',
  build: {
    assets: '_astro'
  },
  trailingSlash: 'always' // Add this line!
});