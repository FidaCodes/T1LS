/** @type {import('tailwindcss').Config} */
export default {
  content: ["./src/**/*.{html,js,jsx}"],
  darkMode: ["class"],
  theme: {
    extend: {
      fontFamily: {
        sans: ['"Fira Code"', "monospace"],
        mono: ['"Fira Code"', "monospace"],
      },
    },
  },
  plugins: [],
};
