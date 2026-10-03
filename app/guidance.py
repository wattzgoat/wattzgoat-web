"""Content for guided mode: which page each flag's exercise starts on, and the
hints for it. Plain data -- no logic -- so it can be read and checked without
the rest of the app.

Each flag with hints has exactly two: a nudge (where to look) and a
technique (what to try). Hints point the way; they never give a ready-made
payload and never contain a flag value.

A flag mapped to BEYOND is one whose exercise doesn't live on a single page
(a hidden page found through robots.txt, another port, the device API, the
assistant). Its hints are shown on the Contact, Terms and Privacy pages.
"""

# Key of the shared setting (stored in lab_meta) that an instructor switches on
# to let participants use guided mode. Resets carry it over.
GUIDED_META_KEY = "guided_mode"

BEYOND = "beyond"
BEYOND_ENDPOINTS = ("pages.contact", "pages.terms", "pages.privacy")

# flag key -> endpoint of the page where the exercise starts (or BEYOND).
FLAG_PAGE = {
    "HEADERS_TEACH": "customer.dashboard",
    "HEADERS_EXERCISE": "auth.login",
    "HEADERS_CLICKJACK": "customer.recharge",
    "SQLI_TEACH": "admin.meters",
    "SQLI_EXERCISE": "admin.alarms",
    "SQLI_BONUS": "customer.usage",
    "SQLI_BOOLEAN_BONUS": "customer.usage",
    "RXSS_TEACH": "customer.usage",
    "RXSS_EXERCISE": "auth.forgot_password",
    "SXSS_TEACH": "customer.dashboard",
    "SXSS_EXERCISE": "customer.support",
    "WEAKPW_TEACH": "auth.signup",
    "WEAKPW_EXERCISE": "auth.login",
    "WEAKPW_CHANGE": "customer.account",
    "RATELIMIT_TEACH": "auth.login",
    "RATELIMIT_EXERCISE": "auth.forgot_password",
    "DEVADMIN_LEAK": "auth.login",
    "FIELDTECH_LOOKUP": BEYOND,
    "IDOR_TEACH": "customer.dashboard",
    "MASSASSIGN_EXERCISE": "customer.account",
    "ROLE_ESCALATION_BONUS": "customer.account",
    "ACCOUNT_IDOR_BONUS": "customer.account",
    "PRIVESC_TEACH": "admin.meter_detail",
    "OLDTOKEN_EXERCISE": "auth.reset_password",
    "SESSIONREUSE_BONUS": "customer.dashboard",
    "PWCHANGE_TEACH": "customer.account",
    "TRAVERSAL_TEACH": "customer.bills",
    "CMDINJECT_EXERCISE": BEYOND,
    "SESSIONID_TEACH": "customer.dashboard",
    "JWT_EXERCISE": BEYOND,
    "PLAINTEXT_TEACH": BEYOND,
    "PLAINTEXT_EXERCISE": BEYOND,
    "BUSLOGIC_TEACH": "customer.recharge",
    "BUSLOGIC_EXERCISE": "customer.solar",
    "BUSLOGIC_NEGATIVE_RECHARGE": "customer.recharge",
    "BUSLOGIC_NEGATIVE_SOLAR": "customer.solar",
    "ERRHANDLING_TEACH": "customer.usage",
    "ERRHANDLING_EXERCISE": "auth.login",
    "INFOLEAK_TEACH": "customer.recharge",
    "CSRF_TEACH": "customer.account",
    "CSRF_EXERCISE": "customer.dashboard",
    "FILEUPLOAD_TEACH": "admin.meter_detail",
    "FILEUPLOAD_EXERCISE": "admin.meter_detail",
    "ASSISTANT_SYSPROMPT_LEAK": BEYOND,
    "ASSISTANT_DIRECT_ACTION": BEYOND,
    "ASSISTANT_DIRECT_DATALEAK": BEYOND,
    "ASSISTANT_INDIRECT_INJECTION": BEYOND,
    "ASSISTANT_OUTPUT_XSS": BEYOND,
}

# flag key -> (nudge, technique). The first batch covers one flag per category.
HINTS = {
    "HEADERS_TEACH": (
        "Every page load carries information your browser doesn't show you. Open your browser's developer tools, go to the Network tab, reload this page, and look at what the server sent back.",
        "Look at the response headers rather than the page itself. Compare them with the protective headers a site should send (anything about framing, content sniffing or transport security) and note which are missing. Something unusual may be sitting among the ones that are there.",
    ),
    "SQLI_TEACH": (
        "That search box talks to the database. Before you try anything clever, find out what happens when you type something it wasn't expecting.",
        "Try a single quote on its own. If the page complains, your input is being pasted into the database's question. From there, look up how UNION lets you add extra rows to a query's answer, and work out how many columns this one returns.",
    ),
    "RXSS_TEACH": (
        "Search for something that doesn't exist and watch how the page repeats your words back to you. Anywhere a page echoes your input, ask whether it treats it as plain text or as part of its own code.",
        "Try searching for a tiny piece of HTML, such as a bold tag, and see whether it shows up as formatting. If it does, try something that runs script, and think about what a script on this page can read from your own browser.",
    ),
    "SXSS_TEACH": (
        "Some things you type are saved and shown again later, perhaps to other people. Look for something on your dashboard that you can rename, and notice where else that name appears.",
        "Save a name that contains a little HTML, then reload the page. If it runs as code instead of showing as text, the page is trusting what was stored. Think about what a script can read about the page it is running in.",
    ),
    "WEAKPW_TEACH": (
        "When you create an account, what does the form insist on? Find out how little it asks for.",
        "Try the weakest password you can think of, even a single character, and see whether the sign-up goes through. A strong system would refuse. If this one doesn't, the page that follows has something for you.",
    ),
    "RATELIMIT_TEACH": (
        "What happens if you get the password wrong over and over? Keep going and watch whether the site ever pushes back.",
        "Try six or more wrong passwords in a row for the same email. If nothing stops you, the page may have changed in a way you can't see on screen. Look at the page's raw source instead of the rendered page.",
    ),
    "FIELDTECH_LOOKUP": (
        "Websites often tell search engines which places to skip, and that list is public. Have a look at what this site asks them to stay away from.",
        "Open one of the places listed there directly. Try a real meter code, then compare what the page shows you with everything the server actually sent back, using your browser's network tools.",
    ),
    "IDOR_TEACH": (
        "Your dashboard fills itself in by asking the server for your meter's readings. Open your browser's network tools and watch what it asks for.",
        "Find the request that fetches readings and look at how it names the meter. Ask for a different meter, staying logged in as yourself, and see whether the server objects.",
    ),
    "PRIVESC_TEACH": (
        "Admin pages contain buttons that do things. Look at what an admin can do to a meter here, and note exactly what the browser sends when you use it.",
        "Now ask whether the server checks who is allowed to do that, or only that someone is signed in. Try sending that same request while logged in as an ordinary customer.",
    ),
    "TRAVERSAL_TEACH": (
        "Look closely at the address you use to download a bill. It describes where a file lives. What happens if you change part of it?",
        "Your bill sits in a folder named after your meter. Try pointing the path at a neighbour's folder instead, using the usual \"go up one level\" notation to get there from your own.",
    ),
    "SESSIONID_TEACH": (
        "Your login is a small value your browser sends with every request. Find it in your browser's storage tools and look at what kind of value it is.",
        "If your value looks like a simple number, think about who holds the numbers before it. Try replacing it with a much smaller one and reload the dashboard. Nobody told you about every account on this site.",
    ),
    "PLAINTEXT_TEACH": (
        "This site answers on more than one port. Find out whether any of them skips encryption.",
        "Log in through the unencrypted one while watching the traffic with a proxy or a packet capture tool, and read the request as it travels. Look at everything the form sends, not just what you typed.",
    ),
    "BUSLOGIC_TEACH": (
        "Pages that handle money are worth a careful read. Look at the page's source, not just what it shows, and list every field that takes part in the calculation.",
        "Some fields never reach the server in a normal submission. If you spot one, build the request yourself and add it, then see whether the server trusts your number over its own sum.",
    ),
    "ERRHANDLING_TEACH": (
        "What does the search do when you give it something it can't make sense of? Try breaking it on purpose.",
        "Submit a single quote and read the error closely. A good error says almost nothing. This one may say far too much.",
    ),
    "CSRF_TEACH": (
        "Look at the form that changes your password. What does it send besides the new password, and what is missing that you'd expect?",
        "Think about what a different website could do if it could make your browser send this exact request while you're logged in here. Build a small page of your own that does it, and open it in the same browser.",
    ),
    "FILEUPLOAD_TEACH": (
        "Somewhere on a meter's admin page you can upload a file. Find it, and think about what the server ought to check before accepting one.",
        "Try uploading a file that has nothing to do with firmware, such as a plain text file, and see whether anything stops you.",
    ),
    "ASSISTANT_DIRECT_ACTION": (
        "The assistant will do things for you, but only some things. Ask it to do something it should refuse and see how it answers.",
        "Notice the difference between a plain request and the same request wrapped in instructions to set its rules aside. Which one does it follow?",
    ),
}
