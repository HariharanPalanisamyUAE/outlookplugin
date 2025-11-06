/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Cybersecurity dark theme colors
        cyber: {
          dark: '#0a0e27',
          darker: '#060913',
          primary: '#00f0ff',
          secondary: '#7000ff',
          success: '#00ff94',
          warning: '#ffb800',
          danger: '#ff006e',
          info: '#0066ff',
        },
        slate: {
          850: '#1a1f36',
          950: '#0f1219',
        }
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
        'gradient-cyber': 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
        'gradient-security': 'linear-gradient(to right, #0f2027, #203a43, #2c5364)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
        'scan': 'scan 2s linear infinite',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px rgba(0, 240, 255, 0.5)' },
          '100%': { boxShadow: '0 0 20px rgba(0, 240, 255, 0.8)' },
        },
        scan: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100%)' },
        }
      },
      boxShadow: {
        'cyber': '0 0 20px rgba(0, 240, 255, 0.3)',
        'cyber-lg': '0 0 40px rgba(0, 240, 255, 0.5)',
      }
    },
  },
  plugins: [],
}
