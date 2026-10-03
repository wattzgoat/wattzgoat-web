/** Compiles the utilities the templates use into a static stylesheet.
 *  Brand colors live here so templates can use bg-ink, text-accent and so on. */
module.exports = {
  content: ["./templates/**/*.html"],
  theme: {
    extend: {
      colors: {
        ink: { DEFAULT: "#14181C", 700: "#2A323A" },
        accent: { DEFAULT: "#F4B41A", 100: "#FDF1CE", 700: "#8F5F00" },
        canvas: "#F2EFE9",
      },
      fontFamily: {
        sans: [
          "-apple-system", "BlinkMacSystemFont", "'Segoe UI'", "Roboto",
          "Helvetica", "Arial", "sans-serif",
        ],
      },
      boxShadow: {
        card: "0 1px 2px rgba(20,24,28,0.04), 0 8px 24px -8px rgba(20,24,28,0.10)",
        lift: "0 2px 4px rgba(20,24,28,0.06), 0 16px 32px -12px rgba(20,24,28,0.18)",
      },
      keyframes: {
        "fade-up": {
          "0%": { opacity: "0", transform: "translateY(12px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
      animation: {
        "fade-up": "fade-up 0.6s ease-out both",
      },
    },
  },
  plugins: [],
};
