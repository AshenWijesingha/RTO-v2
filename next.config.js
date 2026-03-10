/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'export',
  basePath: process.env.NEXT_PUBLIC_BASE_PATH || '',
  assetPrefix: process.env.NEXT_PUBLIC_BASE_PATH || '',
  images: {
    unoptimized: true,
  },
  trailingSlash: true,
  eslint: {
    // Run ESLint separately via `npm run lint` rather than during `next build`.
    // This avoids circular-reference issues when using flat config with Next.js 15.
    ignoreDuringBuilds: true,
  },
}

module.exports = nextConfig
