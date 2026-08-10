/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        navy: {
          DEFAULT: "#0b1f3a",
          950: "#060f1f",
          800: "#122a4d",
        },
        "brand-blue": "#2f6bff",
        "brand-purple": "#8b5cf6",
      },
    },
  },
  plugins: [],
};
