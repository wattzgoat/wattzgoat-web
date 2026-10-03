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

HINTS.update({
    "HEADERS_EXERCISE": (
        "Not every page sends the same headers. Look at what the sign-in page sends before you are even logged in, and compare it with what a logged-in page sends.",
        "Check the sign-in page's response headers against the same checklist you'd use anywhere: framing, content sniffing, transport security and a content security policy. Note what is missing, and look for anything that doesn't belong.",
    ),
    "HEADERS_CLICKJACK": (
        "Pages that handle money deserve a second look. Open the recharge page's source and your browser's network tools, and think about every value that decides whose meter gets the credit.",
        "Some requests accept more fields than the form shows. Try adding one that names a meter, then think about how a page you don't control could get you to submit it without noticing. Build a decoy page with an invisible frame over a button and try it while you are logged in.",
    ),
    "SQLI_EXERCISE": (
        "Admin tools have search boxes too. Try the alarms search the same way you would any other box that talks to a database.",
        "A lone quote tells you whether your input reaches the query. This page returns a fixed number of columns from the alarms table, so the extra rows you add with UNION have to match that count.",
    ),
    "SQLI_BONUS": (
        "You've seen what a search box can do on an admin page. Does the usage search on your own account behave the same way?",
        "If it does, you can add rows from tables you shouldn't see. Work out how many columns the query returns, then ask for readings from every meter, not just yours.",
    ),
    "SQLI_BOOLEAN_BONUS": (
        "There is an easier way into the same search than adding rows: make the question always true instead.",
        "Try ending your search with a quote followed by a condition that is true for every row, then comment out the rest of the query. How the query ends decides whether this works.",
    ),
    "RXSS_EXERCISE": (
        "Even a 'not found' message is output. Ask for a password reset for an address that doesn't exist and see whether the page repeats what you typed.",
        "Use a made-up email address that contains a little HTML. If it comes back as code, think about what a script can read about the page it runs in, other than a cookie.",
    ),
    "SXSS_EXERCISE": (
        "Two kinds of people use this app: customers who write things and admins who read them. Find somewhere you can write something an admin will later see.",
        "Put a little HTML in what you send, then sign in as an admin in a separate browser and open the page where those messages are listed. Think about what a script can find in the page's head.",
    ),
    "WEAKPW_EXERCISE": (
        "Some accounts come with the system. Think about who set up the admin accounts, and whether anyone ever made them choose their own password.",
        "Try the most obvious default password for a shared admin account. A strong system would force it to change on the first sign-in.",
    ),
    "WEAKPW_CHANGE": (
        "You've seen what the sign-up form accepts. Does the change-password form hold itself to the same standard?",
        "Change your password to something very short and simple. If it is accepted, the page that follows has something for you.",
    ),
    "RATELIMIT_EXERCISE": (
        "Signing in isn't the only form that can be hammered. Find another form that asks for an email address, and keep using it.",
        "Send the same request with the same email six or more times. If nothing stops you, look at the page's raw source rather than the page itself.",
    ),
    "DEVADMIN_LEAK": (
        "Developers leave notes for themselves. Look at the sign-in page the way a developer would, not just the way a visitor would.",
        "View the page's source and read everything in it, including parts you can't see on screen. If you find a credential, try it, and see where it takes you.",
    ),
    "MASSASSIGN_EXERCISE": (
        "The account page saves your details through a request your browser sends in the background. Capture it and compare what it sends with what the form shows you.",
        "Look for a field the form never lets you edit but still sends. Change its value and send the request yourself, and see whether the server accepts it.",
    ),
    "ROLE_ESCALATION_BONUS": (
        "Among the fields the account form sends in the background, is there one that describes what you are allowed to do?",
        "Change that field to something more powerful and send the request yourself. If the server believes you, check which pages you can now reach.",
    ),
    "ACCOUNT_IDOR_BONUS": (
        "Look at who the account update says it is for. The request may name an account as well as the changes.",
        "Change that identifier to another person's and send the request yourself. The server may apply your changes to them instead of you.",
    ),
    "OLDTOKEN_EXERCISE": (
        "A password reset link carries a token. Request a reset for your own account and look closely at what the token is made of.",
        "If the token is just an encoded address and a time, think about what that means for someone who isn't you. Build your own token for another account, use it to set a new password, then sign in as that account in the same browser.",
    ),
    "SESSIONREUSE_BONUS": (
        "Signing out should end a session for good. Capture your session value before you log out, and see what the server does with it afterwards.",
        "After logging out, send a request with the old session value. If the server still treats you as signed in, logging out only cleared your browser.",
    ),
    "PWCHANGE_TEACH": (
        "Changing a password is a sensitive moment. Look at what the form asks you to prove before it makes the change.",
        "Choose a new password longer than seven characters and submit the form without proving who you are. A careful system would ask for the old password first.",
    ),
    "CMDINJECT_EXERCISE": (
        "Some tools are meant for staff but aren't linked from anywhere. Check what the site's public files ask search engines to skip, and see whether any of those places are really protected.",
        "Find a tool that passes your input to the system. Try adding a second command after the address using a separator, and see whether it runs too.",
    ),
    "JWT_EXERCISE": (
        "Devices don't log in the way people do; they carry a signed token. Find the endpoint they report readings to, and look at what the token contains.",
        "Decode the token and look at the header that says how it was signed. Think about what happens if you claim it wasn't signed at all, and name a different meter in the payload.",
    ),
    "PLAINTEXT_EXERCISE": (
        "The device endpoint answers on more than one port. Find out what happens when a device reports a reading without encryption.",
        "Send the same device request to the unencrypted port while watching the traffic. Everything the device sends, including its token, is readable.",
    ),
    "BUSLOGIC_EXERCISE": (
        "The solar page believes what you tell it. Think about what a real household could export in one go, and whether the app checks.",
        "Report an export far larger than any house could produce, and see what you are paid.",
    ),
    "BUSLOGIC_NEGATIVE_RECHARGE": (
        "Money fields have two ends. You've tested how big a number can be; what about the other end?",
        "Submit a negative amount on the recharge form and watch what happens to the balance.",
    ),
    "BUSLOGIC_NEGATIVE_SOLAR": (
        "The solar form has the same two ends to test: how big, and how small.",
        "Report a negative export and see how the balance changes.",
    ),
    "INFOLEAK_TEACH": (
        "Give a form something of the wrong kind and see how the app copes. A number field is a good place to start.",
        "On the recharge page, submit something that isn't a number. Read the response closely for things a user should never see.",
    ),
    "CSRF_EXERCISE": (
        "Your browser sends your session along with any request to the site. Look for another form that changes something without proving the request came from the page.",
        "The meter rename form is a quiet example. Build a small page that submits it automatically, open it in the same browser while you are signed in, then check the request and response rather than the page.",
    ),
    "FILEUPLOAD_EXERCISE": (
        "The file's name is chosen by whoever sends it. Think about what the server does with that name.",
        "Upload a file whose name includes the notation for 'go up one folder', then check where it actually landed. There is a page that shows a file kept outside the usual folder.",
    ),
    "ASSISTANT_SYSPROMPT_LEAK": (
        "Assistants are given instructions you don't normally see. Ask it plainly what they are, and see how it answers.",
        "If it refuses, try the same ask after telling it to set its earlier instructions aside.",
    ),
    "ASSISTANT_DIRECT_DATALEAK": (
        "The assistant can look people up. Ask about someone else's account and see what it will say.",
        "Ask for another customer's address after telling it to ignore its restrictions, and compare that with asking without the extra instruction.",
    ),
    "ASSISTANT_INDIRECT_INJECTION": (
        "Sometimes the instruction doesn't come from the person talking to the assistant. Think about text that someone else wrote, which the assistant later reads for you.",
        "Write a support request containing instructions meant for the assistant, then sign in as an admin and ask it to summarize your newest ticket.",
    ),
    "ASSISTANT_OUTPUT_XSS": (
        "What the assistant says is shown on the page. Think about whether the page treats its words as text or as markup.",
        "Send something that would run if it were treated as code. A bare tag may not do anything on its own, so think about what makes a tag run by itself.",
    ),
    "ERRHANDLING_EXERCISE": (
        "Compare what the sign-in page says when the email doesn't exist with what it says when the email is real but the password is wrong.",
        "Try both cases and compare the messages word for word. A page that tells you which part was wrong helps an attacker more than it helps you.",
    ),
})
