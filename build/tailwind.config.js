/** Scans the actual Jinja templates for class names (including Tailwind's
 *  arbitrary-value bracket syntax, e.g. bg-[#F2EFE9]) and compiles only the
 *  utilities this app actually uses into a static stylesheet -- replacing
 *  the Play CDN script, which only works by re-scanning the DOM client-side
 *  every page load and requires fetching that script from the internet.
 *
 *  Brand tokens live here so templates can say bg-ink / text-accent
 *  instead of repeating hex values. Pages not yet moved over still use the
 *  arbitrary-value form, which keeps working alongside these. */
module.exports = {
  content: ["./templates/**/*.html"],
  theme: {
    extend: {
      colors: {
        ink: { DEFAULT: "#14181C", 700: "#2A323A", 800: "#1C2228" },
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
