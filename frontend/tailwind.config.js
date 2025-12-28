/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        sinx: {
          primary: '#0066ff',
          secondary: '#00ccff',
          dark: '#0a0e27',
          darker: '#050714',
        },
        threat: {
          critical: '#dc2626',
          high: '#ea580c',
          medium: '#f59e0b',
          low: '#10b981',
        },
      },
    },
  },
  plugins: [],
}
