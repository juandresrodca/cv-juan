import { defineCollection, z } from 'astro:content';

const blog = defineCollection({
  type: 'content',
  schema: z.object({
    title: z.string(),
    date: z.date(),
    summary: z.string(),
    tags: z.array(z.string()),
    draft: z.boolean().default(false),
    // Optional — add to a post to show a hero image at the top
    heroImage: z.string().optional(),
    // Optional — short label rendered as a badge pill next to the title
    badge: z.string().optional(),
  }),
});

export const collections = { blog };
