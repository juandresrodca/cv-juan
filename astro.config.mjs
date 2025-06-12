import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';
import react from '@astrojs/react';

export default defineConfig({
  integrations: [tailwind(), react()],
  
  site: 'https://juandresrodca.github.io',
  
  base: '/cv-juan',
  output: 'static', // Crucial para el hosting de sitios estáticos como GitHub Pages
  build: {
    assets: '_astro' // Directorio por defecto para los assets compilados
  }
});
