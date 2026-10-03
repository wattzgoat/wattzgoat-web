# WattzGOAT

WattzGOAT is an intentionally vulnerable web application built to be hacked. It is a made-up smart meter company with a customer portal, and it's a lab, not a real product. Customers can check their meter, top up their balance, report solar power, look at bills and contact support. Admins can manage meters and look after support tickets.

The site is vulnerable on purpose, so you can practise finding real security weaknesses in a safe place.

![Login page](docs/screenshots/login.png)

## Key features

- A full customer portal (signup, meter dashboard, recharge, solar export, bills, support tickets) plus an admin side, so there's a realistic amount of surface to explore, not just a single vulnerable form.
- 48 hidden weaknesses to find and exploit, from easy to hard.
- A capture-the-flag style Progress page that tracks which ones you've found.
- A simulated AI assistant with its own set of weaknesses to find.
- Once you have found a flag, you can see the vulnerable code next to the fixed code, in Python, JavaScript and PHP, so you learn what caused the problem and how to fix it.
- An optional guided mode that gives hints for the page you are on, without giving the answer away (see [Guided mode](#guided-mode)).
- Runs as a single Docker container with no other setup. For groups, an optional instructor dashboard runs alongside it (see [Instructor mode](#instructor-mode)).

## How you learn with it

WattzGOAT works like a capture the flag (CTF) game. There are 48 flags hidden in the site. You get a flag by finding a weakness and using it. Five of the 48 are bonus flags about a simulated AI assistant.

The weaknesses are the kind of problems described in the OWASP Top 10, things like broken access control and injection, so what you practise here applies to real websites too.

To get started, create an account or log in with one of the sample customer accounts, then look around and try things out. When you find a flag, you can enter it on the Progress page, which keeps track of the ones you have found.

Once you have found a flag, select **View code** next to it on the Progress page. It shows the vulnerable code and the fixed code side by side, with the lines that changed highlighted, a short note on why the fix works, and tabs for Python, JavaScript and PHP. Each flag's code unlocks only when you have found that flag.

![Progress page](docs/screenshots/progress.png)

Sample customer accounts have emails like `alice.smith@example.com`. Their passwords are the first name followed by `123`.

## Quick start

If you already have Docker installed, this gets you running in one step. See "What you need" and "Start WattzGOAT" below for the full explanation.

```
docker run -d --name wattzgoat -p 5000:5000 -p 5001:5001 -e INSTANCE_HOST=127.0.0.1 -e STANDALONE=true -e STANDALONE_PASSWORD=YourPasswordHere ghcr.io/wattzgoat/wattzgoat-web:latest
```

Then open https://127.0.0.1:5000 in your browser.

## How it fits together

WattzGOAT runs as a single container: the web app and its database both live inside it, reachable over two ports (one HTTPS, one plain HTTP; a couple of the exercises specifically need the unencrypted one). Nothing else needs to be installed or run alongside it.

![Architecture diagram: your browser connects to the WattzGOAT container over HTTPS on port 5000 and HTTP on port 5001; inside the container, the Flask web app talks to a SQLite database stored in a Docker volume](docs/architecture.svg)

## Warning

**This site is insecure on purpose.**

- Run it only on your own computer, or on a private network that you control.
- Never put it on the internet.
- Never type real passwords or personal details into it.

All company names, accounts and data in the site are made up.

## Built with AI

This project was built with the help of AI tools and contains AI-written code. The weaknesses are there on purpose, but the code may also have other bugs or security problems that were not planned. Please keep this in mind and follow the warning above.

## What you need

- A computer running Windows, macOS or Linux.
- An internet connection for the first setup.
- **Docker**, to run the site. Follow the official install steps at https://docs.docker.com/get-started/get-docker/.
- **Git**, only if you want to build the site from the source code. Follow the official install steps at https://git-scm.com/downloads.

To check that Docker works, run these two commands. If the second one prints a "Hello from Docker!" message, you are ready.

```
docker --version
docker run --rm hello-world
```

## Start WattzGOAT

You can either use the ready-made image or build it yourself. Both give you the same site. Use the same commands on Linux, macOS and Windows (in PowerShell).

### Option 1: use the ready-made image

```
docker run -d --name wattzgoat -p 5000:5000 -p 5001:5001 -e INSTANCE_HOST=127.0.0.1 -e STANDALONE=true -e STANDALONE_PASSWORD=YourPasswordHere ghcr.io/wattzgoat/wattzgoat-web:latest
```

Docker downloads the image the first time you run this.

### Option 2: build it from the source code

```
git clone https://github.com/wattzgoat/wattzgoat-web.git
cd wattzgoat-web
docker build -t wattzgoat .
docker run -d --name wattzgoat -p 5000:5000 -p 5001:5001 -e INSTANCE_HOST=127.0.0.1 -e STANDALONE=true -e STANDALONE_PASSWORD=YourPasswordHere wattzgoat
```

The build downloads some packages, so it needs an internet connection and takes a few minutes.

### What the settings mean

| Setting | What it does |
| --- | --- |
| `-p 5000:5000` | Makes the site available on port 5000 (HTTPS). |
| `-p 5001:5001` | Makes the site also available on port 5001 (plain HTTP). Some exercises use it, so keep both ports. |
| `INSTANCE_HOST` | The IP address you will type into your browser. Use `127.0.0.1` if the browser is on the same computer. If you run WattzGOAT on another machine, use that machine's IP address, for example `192.168.1.50`. It must be an IP address, not a name. |
| `STANDALONE` | Set to `true` when you run a single copy on its own. |
| `STANDALONE_PASSWORD` | A password of your choice. Replace `YourPasswordHere` with your own. |
| `GUIDED_MODE` | Optional. Set to `true`, together with `STANDALONE=true`, to let participants switch on [guided mode](#guided-mode). Leave it out otherwise. |

### Open the site

Go to https://127.0.0.1:5000 in your browser (or use the IP address you set in `INSTANCE_HOST`).

Your browser will warn you that the connection is not private. This is normal, because the site makes its own security certificate. Choose **Advanced**, then continue to the site.

## Instructor mode

Instructor mode adds a second site, the instructor dashboard, that runs next to the normal site and helps you run WattzGOAT with a group. You log in to it separately, with instructor accounts you create.

- **Vulnerability switches.** Turn any single vulnerability, or a whole group of them, from vulnerable to fixed and back while people watch. Showing the same page both ways is a good way to see what a fix really changes.
- **Code examples.** A Code Examples page shows the vulnerable and fixed code for every vulnerability, side by side, in Python, JavaScript and PHP. Switch one vulnerability on to show it, or switch a whole group on. It is your view for teaching and never changes what participants can see: they unlock each flag's code on their own Progress page by finding the flag.
- **Guided mode.** Offer [guided mode](#guided-mode) to participants with one switch. It is off by default and stays as you set it through every reset.
- **Participant leaderboard.** A live list of everyone taking part, ranked by flags found, with their latest activity. Select **View** to see which flags a person has found and which are left, in the same order as their Progress page. Select **Reset** at the end of a person's row to clear that person's progress without touching anyone else's. Use **Export CSV** to download a summary of everyone's progress, or a per-flag detail file.
- **Three ways to reset.**

| Reset | What it does |
| --- | --- |
| **Reset Lab** | Starts completely fresh. The site goes back to its original state, every switch returns to vulnerable, flag values change, and everyone's progress and nicknames are cleared. |
| **Reset App** | Restores the shop's own data (accounts, meters, tickets) and returns every switch to vulnerable, but keeps everyone's progress, nicknames and flag values. |
| **Reset All Redemptions** | Clears everyone's progress only. Nothing else changes. |

### Running a competition instead?

You can skip instructor mode. If you start a single copy as in the Quick start (with `STANDALONE=true` and your `STANDALONE_PASSWORD`), it includes a hidden page at https://127.0.0.1:5000/participants. Sign in with your `STANDALONE_PASSWORD` to get the same participant leaderboard described above, including **Export CSV**. To offer guided mode there too, start the copy with `GUIDED_MODE=true` as well.

### Before you start

- Everything in [What you need](#what-you-need) above.
- Two instructor accounts. Choose an email and a password for each. Instructor mode needs both.
- One Docker volume shared by the normal site and the dashboard, so the dashboard can see and control the site. Docker Compose creates it for you. With plain Docker commands you create it with one command.
- Leave out the `STANDALONE` settings from the Quick start. Instructor mode replaces them.

### Start with Docker Compose

1. Get the file `docker-compose.instructor.yml` from the main folder of the project. Clone the project as in "Option 2: build it from the source code" above, or download just that file from GitHub.
2. In the same folder, create a file named `.env` containing your instructor accounts:

   ```
   TRAINER1_EMAIL=instructor1@example.com
   TRAINER1_PASSWORD=YourPasswordHere
   TRAINER2_EMAIL=instructor2@example.com
   TRAINER2_PASSWORD=YourPasswordHere
   ```

   Replace the emails and passwords with your own, and avoid the `$` character in passwords. If your browser is on a different computer, also add `INSTANCE_HOST=192.168.1.50` (use the IP address of the machine running Docker). If you built the image from source, also add `WATTZGOAT_IMAGE=wattzgoat`.
3. Start both sites:

   ```
   docker compose -f docker-compose.instructor.yml up -d
   ```

To stop them, run `docker compose -f docker-compose.instructor.yml down`. Progress is kept. Add `-v` to the end of that command to delete it too.

### Start with Docker commands

Create the shared volume, then start the normal site **first**, then the dashboard. Replace the emails and passwords with your own.

```
docker volume create wattzgoat-data
docker run -d --name wattzgoat -p 5000:5000 -p 5001:5001 -e INSTANCE_HOST=127.0.0.1 -v wattzgoat-data:/app/data ghcr.io/wattzgoat/wattzgoat-web:latest
docker run -d --name wattzgoat-instructor -p 5004:5004 -e TRAINER_DASHBOARD=true -e INSTANCE_HOST=127.0.0.1 -e PARTICIPANT_BASE_URL=https://127.0.0.1:5000 -e TRAINER1_EMAIL=instructor1@example.com -e TRAINER1_PASSWORD=YourPasswordHere -e TRAINER2_EMAIL=instructor2@example.com -e TRAINER2_PASSWORD=YourPasswordHere -v wattzgoat-data:/app/data ghcr.io/wattzgoat/wattzgoat-web:latest
```

If the browser is on a different computer, use the IP address of the machine running Docker instead of `127.0.0.1`, in all three places. If you built the image from source, use `wattzgoat` instead of `ghcr.io/wattzgoat/wattzgoat-web:latest`.

### Open the dashboard

Go to https://127.0.0.1:5004 and log in with one of your instructor accounts. Everyone else uses the normal site at https://127.0.0.1:5000. Your browser will show the same security warning as before.

## Guided mode

Guided mode gives you hints for the page you are on. It is for when you want a nudge, and it never gives the answer away. It is off unless the person running WattzGOAT turns it on.

### Turning it on

- **With instructor mode.** The instructor switches on **Guided mode** on the dashboard. Each participant then sees a **Guided mode** switch in their header and chooses for themselves whether to use it. It never switches on for anyone else using the same site. It stays as the instructor set it through every reset.
- **Running on your own.** Start the copy with `STANDALONE=true` and `GUIDED_MODE=true`. Everyone using it then sees the switch and chooses for themselves.
- **Otherwise** guided mode is not offered at all, and there is no switch.

### What you see

When it is on, a bar sits along the bottom of the page, over the content, and stays there as you scroll. Use **Minimize** to tuck it down to one line.

- **The headline** says how many flags are on the page and how many you have found. A page with no flags says so.
- **Each flag you have not found** has its own card, labelled like "Flag 3 of 6". The number is that flag's place among all the flags on the page, so it matches the headline and does not change when you find another one.
- **Each card has two hints**, shown one at a time: first a nudge about where to look, then the technique to try. Use **Show next hint** and **Previous hint** to move between them.
- **To move between flags**, use the arrows or the numbered tabs. They are separate from the hint buttons, so moving to another flag leaves each flag's hint where you left it.
- **When you find a flag**, its card goes away. You can still open its code from the Progress page.
- **If your instructor has fixed a vulnerability**, its card says so and suggests confirming that it can no longer be exploited.
- **Some exercises do not belong to a single page**: a hidden page found through the site's own files, another port, the device API, or the assistant. Their hints are under **Beyond the browser** on the Contact, Terms and Privacy pages.

The Progress page has no bar. To turn guided mode off, use the switch in the header. Hints are shown one at a time to pace you, but they are not locked away.

## Everyday commands

| What you want to do | Command |
| --- | --- |
| See that it is running | `docker ps` |
| Read the logs | `docker logs wattzgoat` |
| Stop it | `docker stop wattzgoat` |
| Start it again (keeps your progress) | `docker start wattzgoat` |
| Start again from scratch | `docker rm -f wattzgoat`, then run the start command again |

Removing the container clears everything, including the flags you have found.

**To update to a newer version**

Get the new version first, then replace the old container. Updating clears your progress, because the old container is removed.

- Ready-made image:
  1. `docker pull ghcr.io/wattzgoat/wattzgoat-web:latest`
  2. `docker rm -f wattzgoat`
  3. Run the start command again.
- Built from source:
  1. `git pull`
  2. `docker build -t wattzgoat .`
  3. `docker rm -f wattzgoat`
  4. Run the start command again.

## If something goes wrong

- **"Port is already allocated"**: another program is using that port. Change the number on the left of the port setting, for example `-p 8443:5000`, and open https://127.0.0.1:8443 instead.
- **The page does not load**: run `docker ps` to check the container is running. If it is not, run `docker logs wattzgoat` to see why.
- **The container stops right after starting**: check that `INSTANCE_HOST` is an IP address, such as `127.0.0.1`, and not a name like `localhost`.
- **On Windows or macOS, Docker commands fail**: make sure Docker Desktop is open and running.

## Contributing

Ideas and bug reports are welcome. Please open an issue on the [GitHub Issues page](https://github.com/wattzgoat/wattzgoat-web/issues).

If you would like to add or change something, you can send a pull request. Pull requests are reviewed before they are merged. For bigger changes, please open an issue first so we can talk about it.

The weaknesses in the site are there on purpose, so they are not bugs. Problems that stop the site from working, or weaknesses that were not planned, are worth reporting.

To run the automated tests, you need Python 3.12 and a fresh copy of the site running (see above):

```
pip install -r tests/requirements-dev.txt
pytest tests
```

Set `WATTZGOAT_BASE_URL` to the address of your copy if it is not `https://127.0.0.1:5000`. The tests change data in the site, so use a fresh copy each time.

## License

WattzGOAT is licensed under the MIT License. You are free to use, copy and change it. See the [LICENSE](LICENSE) file for the full terms.

Copyright 2026 WattzGOAT
