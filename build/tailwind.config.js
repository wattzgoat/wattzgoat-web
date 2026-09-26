/** Scans the actual Jinja templates for class names (including Tailwind's
 *  arbitrary-value bracket syntax, e.g. bg-[#F2EFE9]) and compiles only the
 *  utilities this app actually uses into a static stylesheet -- replacing
 *  the Play CDN script, which only works by re-scanning the DOM client-side
 *  every page load and requires fetching that script from the internet. */
module.exports = {
  content: ["./templates/**/*.html"],
  theme: { extend: {} },
  plugins: [],
};
