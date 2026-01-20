/** @type {import('next').NextConfig} */
const nextConfig = {
  // Enable React strict mode for better development experience
  reactStrictMode: true,

  // Environment variables exposed to the browser
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000',
    NEXT_PUBLIC_BLOCKCHAIN_EXPLORER: process.env.NEXT_PUBLIC_BLOCKCHAIN_EXPLORER || 'https://basescan.org',
    NEXT_PUBLIC_ANCHOR_CONTRACT: process.env.NEXT_PUBLIC_ANCHOR_CONTRACT || '',
  },

  // Rewrites for API proxying in development
  async rewrites() {
    return [
      {
        source: '/api/v1/:path*',
        destination: `${process.env.API_URL || 'http://localhost:8000'}/:path*`,
      },
    ];
  },
};

export default nextConfig;
