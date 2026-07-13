/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./pwnAD/web/templates/**/*.html"],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        accent: { DEFAULT: '#ef4444', hover: '#dc2626', subtle: '#fca5a5' }
      }
    }
  },
  plugins: [],
}
