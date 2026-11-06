module.exports = {
      content: ['./index.html', './app.js'],
      plugins: [require('@tailwindcss/forms'), require('@tailwindcss/container-queries')],
      darkMode: "class",
      theme: {
        extend: {
          fontFamily: {
            sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
            mono: ['JetBrains Mono', 'monospace'],
          },
          colors: {
            brand: {
              50: '#f0f5ff',
              100: '#e5edff',
              600: '#1d4ed8',
              700: '#1e40af',
              800: '#1e3a8a',
              900: '#0f172a'
            }
          }
        }
      }
    };
