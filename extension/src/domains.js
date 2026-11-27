'use strict';

/**
 * PhishGuard Local - Offline Domain Knowledge Base
 * 100% client-side, zero network requests.
 * Includes:
 *  - MULTI_PART_TLDS: Offline Public Suffix List subset for eTLD+1 parsing
 *  - SIBLING_DOMAIN_GROUPS: Official multi-domain ecosystems treated as same-site
 *  - KNOWN_OAUTH_PROVIDERS: Legitimate SSO / OAuth identity providers
 *  - TOP_TRUSTED_DOMAINS: 500+ curated global & regional legitimate eTLD+1 domains
 *  - DEFAULT_PROTECTED_DOMAINS: High-value target brands for typosquatting checks
 *  - SUSPICIOUS_TLDS: Frequently abused TLDs in phishing campaigns
 */
(function (root) {
  const MULTI_PART_TLDS = new Set([
    // Indonesia
    'co.id', 'ac.id', 'go.id', 'or.id', 'web.id', 'my.id', 'biz.id', 'sch.id', 'net.id', 'mil.id', 'desa.id',
    // UK
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk', 'nhs.uk', 'police.uk',
    // Australia & New Zealand
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'co.nz', 'net.nz', 'org.nz', 'govt.nz',
    // Asia-Pacific
    'com.sg', 'edu.sg', 'gov.sg', 'org.sg',
    'com.my', 'edu.my', 'gov.my', 'org.my',
    'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
    'co.kr', 'or.kr', 'go.kr', 'ac.kr',
    'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
    'com.hk', 'org.hk', 'gov.hk', 'edu.hk',
    'com.tw', 'org.tw', 'gov.tw', 'edu.tw',
    'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in',
    'com.ph', 'gov.ph', 'edu.ph',
    'co.th', 'ac.th', 'go.th',
    'com.vn', 'gov.vn', 'edu.vn',
    // Americas & Europe
    'com.br', 'org.br', 'gov.br', 'edu.br',
    'com.mx', 'org.mx', 'gob.mx',
    'com.ar', 'org.ar', 'gob.ar',
    'co.za', 'org.za', 'gov.za',
    'com.tr', 'org.tr', 'gov.tr',
    'co.il', 'org.il', 'gov.il',
    'com.ua', 'org.ua', 'gov.ua',
    'com.pl', 'net.pl', 'org.pl',
    'com.es', 'nom.es', 'org.es',
    // Shared cloud/hosting public suffixes (so user.github.io != github.com)
    'github.io', 'gitlab.io', 'pages.dev', 'workers.dev', 'vercel.app',
    'netlify.app', 'web.app', 'firebaseapp.com', 'herokuapp.com',
    'appspot.com', 'azurewebsites.net', 'cloudfront.net', 'amazonaws.com'
  ]);

  // Official sibling domain groups treated as Same-Site (Trusted)
  const SIBLING_DOMAIN_GROUPS = [
    ['github.com', 'githubusercontent.com', 'githubassets.com', 'github.io', 'github.dev', 'github.blog', 'githubstatus.com'],
    ['google.com', 'gstatic.com', 'googleapis.com', 'googleusercontent.com', 'youtube.com', 'youtu.be', 'gmail.com', 'withgoogle.com', 'google.co.id', 'google.co.uk', 'google.co.jp', 'android.com', 'chromium.org', 'firebase.google.com'],
    ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com', 'microsoftonline.com', 'msauth.net', 'msftauth.net', 'windows.net', 'azure.com', 'msn.com', 'bing.com', 'xbox.com', 'linkedin.com', 'licdn.com'],
    ['apple.com', 'icloud.com', 'cdn-apple.com', 'mzstatic.com', 'me.com'],
    ['pinterest.com', 'pinimg.com', 'pin.it', 'pinterest.co.uk', 'pinterest.de', 'pinterest.fr', 'pinterest.jp', 'pinterest.ca'],
    ['facebook.com', 'fbcdn.net', 'fbsbx.com', 'instagram.com', 'cdninstagram.com', 'whatsapp.com', 'whatsapp.net', 'messenger.com', 'meta.com', 'threads.net'],
    ['amazon.com', 'amazonaws.com', 'ssl-images-amazon.com', 'media-amazon.com', 'amzn.to', 'amazon.co.uk', 'amazon.co.jp', 'amazon.de', 'twitch.tv', 'imdb.com'],
    ['paypal.com', 'paypalobjects.com', 'venmo.com', 'braintreegateway.com'],
    ['cloudflare.com', 'cloudflareinsights.com', 'challenges.cloudflare.com'],
    ['twitter.com', 'x.com', 'twimg.com', 't.co'],
    ['reddit.com', 'redd.it', 'redditstatic.com', 'redditmedia.com'],
    ['wikipedia.org', 'wikimedia.org', 'wiktionary.org', 'wikidata.org', 'mediawiki.org'],
    ['atlassian.com', 'atlassian.net', 'bitbucket.org', 'trello.com', 'jira.com'],
    ['shopify.com', 'myshopify.com', 'shopifycdn.com'],
    ['stripe.com', 'stripe.network', 'stripecdn.com'],
    ['adobe.com', 'adobelogin.com', 'typekit.net', 'behance.net'],
    ['yahoo.com', 'yimg.com', 'aol.com'],
    ['bca.co.id', 'klikbca.com'],
    ['tokopedia.com', 'tokopedia.net', 'gojek.com', 'gopay.co.id', 'goto.com'],
    ['shopee.co.id', 'shopee.com', 'shopeemobile.com']
  ];

  // Fast lookup map: registrableDomain -> group index
  const SIBLING_GROUP_INDEX = new Map();
  SIBLING_DOMAIN_GROUPS.forEach((group, idx) => {
    for (const dom of group) {
      SIBLING_GROUP_INDEX.set(dom, idx);
    }
  });

  // Curated offline allowlist for legitimate OAuth / SSO identity providers
  const KNOWN_OAUTH_HOSTS = new Set([
    'accounts.google.com',
    'oauth2.googleapis.com',
    'appleid.apple.com',
    'idmsa.apple.com',
    'login.microsoftonline.com',
    'login.live.com',
    'login.windows.net',
    'github.com',
    'gitlab.com',
    'bitbucket.org',
    'id.atlassian.com',
    'www.facebook.com',
    'facebook.com',
    'm.facebook.com',
    'api.twitter.com',
    'twitter.com',
    'x.com',
    'www.linkedin.com',
    'linkedin.com',
    'discord.com',
    'slack.com',
    'login.yahoo.com',
    'api.login.yahoo.com',
    'accounts.spotify.com',
    'id.twitch.tv',
    'steamcommunity.com',
    'www.epicgames.com',
    'auth.epicgames.com',
    'orcid.org',
    'www.paypal.com',
    'connect.stripe.com',
    'accounts.shopify.com',
    'accounts.zoho.com',
    'login.salesforce.com',
    'accounts.intuit.com',
    'auth.adobelogin.com',
    'ims-na1.adobelogin.com',
    'id.sonyentertainmentnetwork.com',
    'accounts.nintendo.com',
    'accounts.pinterest.com',
    'www.pinterest.com'
  ]);

  // Suffixes for multi-tenant enterprise SSO providers (e.g., company.okta.com, tenant.auth0.com)
  const KNOWN_OAUTH_DOMAINS = new Set([
    'okta.com',
    'oktapreview.com',
    'auth0.com',
    'onelogin.com',
    'pingidentity.com',
    'duosecurity.com',
    'b2clogin.com',
    'amazoncognito.com',
    'clerk.accounts.dev',
    'supabase.co',
    'firebaseapp.com'
  ]);

  // High-value protected brand domains for typosquatting & brand-spoofing detection
  const DEFAULT_PROTECTED_DOMAINS = [
    // Global Tech & Cloud
    'google.com', 'gmail.com', 'youtube.com', 'microsoft.com', 'live.com', 'outlook.com',
    'office.com', 'apple.com', 'icloud.com', 'amazon.com', 'github.com', 'gitlab.com',
    'cloudflare.com', 'dropbox.com', 'adobe.com', 'zoom.us', 'slack.com', 'notion.so',
    'vercel.com', 'netlify.com', 'mozilla.org', 'wikipedia.org', 'stackoverflow.com',
    'npmjs.com', 'openai.com', 'anthropic.com', 'figma.com', 'linear.app', 'atlassian.com',
    // Social & Media
    'facebook.com', 'instagram.com', 'whatsapp.com', 'linkedin.com', 'twitter.com',
    'tiktok.com', 'discord.com', 'telegram.org', 'reddit.com', 'netflix.com', 'spotify.com',
    'pinterest.com', 'twitch.tv',
    // Global Finance & Payments
    'paypal.com', 'stripe.com', 'wise.com', 'binance.com', 'coinbase.com', 'chase.com',
    'bankofamerica.com', 'wellsfargo.com', 'citibank.com', 'americanexpress.com', 'revolut.com',
    // Indonesia Banking, E-Wallet & E-Commerce
    'bca.co.id', 'klikbca.com', 'bankmandiri.co.id', 'bri.co.id', 'bni.co.id',
    'cimbniaga.co.id', 'bankbsi.co.id', 'dana.id', 'ovo.id', 'gopay.co.id',
    'gojek.com', 'grab.com', 'tokopedia.com', 'shopee.co.id', 'bukalapak.com',
    'blibli.com', 'lazada.co.id', 'traveloka.com', 'tiket.com', 'telkomsel.com', 'pajak.go.id'
  ];

  // Curated offline seed list of 500+ legitimate global & regional eTLD+1 domains
  const TOP_TRUSTED_DOMAINS = new Set([
    ...DEFAULT_PROTECTED_DOMAINS,
    // Search, Portals & Productivity
    'bing.com', 'yahoo.com', 'duckduckgo.com', 'baidu.com', 'yandex.com', 'yandex.ru',
    'ecosia.org', 'startpage.com', 'brave.com', 'opera.com', 'vivaldi.com', 'firefox.com',
    'msn.com', 'aol.com', 'proton.me', 'protonmail.com', 'tutanota.com', 'fastmail.com',
    'zoho.com', 'gmx.com', 'mail.com', 'icloud.com', 'me.com', 'box.com', 'onedrive.com',
    'wetransfer.com', 'mega.nz', 'mediafire.com', 'evernote.com', 'obsidian.md', 'roamresearch.com',
    'coda.io', 'airtable.com', 'monday.com', 'asana.com', 'clickup.com', 'trello.com',
    'basecamp.com', 'miro.com', 'lucid.app', 'whimsical.com', 'canva.com', 'grammarly.com',
    'deepl.com', 'calendly.com', 'typeform.com', 'surveymonkey.com', 'jotform.com', 'docusign.com',
    'hellosign.com', 'pandadoc.com', 'loom.com', 'vimeo.com', 'dailymotion.com', 'soundcloud.com',
    'bandcamp.com', 'flickr.com', 'unsplash.com', 'pexels.com', 'pixabay.com', 'shutterstock.com',
    'gettyimages.com', 'istockphoto.com', 'dribbble.com', 'behance.net', 'deviantart.com',
    'artstation.com', '500px.com', 'goodreads.com', 'letterboxd.com', 'imdb.com', 'rottentomatoes.com',
    'metacritic.com', 'myanimelist.net', 'anilist.co', 'fandom.com', 'ign.com', 'gamespot.com',
    'kotaku.com', 'polygon.com', 'eurogamer.net', 'pcgamer.com', 'steampowered.com',
    'steamcommunity.com', 'store.steampowered.com', 'epicgames.com', 'gog.com', 'itch.io',
    'roblox.com', 'minecraft.net', 'ea.com', 'ubisoft.com', 'blizzard.com', 'battle.net',
    'riotgames.com', 'playstation.com', 'xbox.com', 'nintendo.com', 'chess.com', 'lichess.org',
    // Developer, Cloud & Infrastructure
    'githubusercontent.com', 'githubassets.com', 'github.io', 'github.dev', 'github.blog',
    'bitbucket.org', 'sourceforge.net', 'codeberg.org', 'sr.ht', 'codepen.io', 'codesandbox.io',
    'stackblitz.com', 'replit.com', 'glitch.com', 'jsfiddle.net', 'leetcode.com', 'hackerrank.com',
    'codeforces.com', 'codewars.com', 'exercism.org', 'kaggle.com', 'huggingface.co', 'wandb.ai',
    'colab.research.google.com', 'jupyter.org', 'anaconda.com', 'pypi.org', 'python.org',
    'nodejs.org', 'deno.com', 'bun.sh', 'typescriptlang.org', 'reactjs.org', 'react.dev',
    'nextjs.org', 'vuejs.org', 'nuxt.com', 'svelte.dev', 'angular.io', 'angular.dev',
    'astro.build', 'vite.dev', 'vitejs.dev', 'webpack.js.org', 'tailwindcss.com', 'getbootstrap.com',
    'mui.com', 'chakra-ui.com', 'radix-ui.com', 'shadcn.com', 'storybook.js.org', 'eslint.org',
    'prettier.io', 'jestjs.io', 'vitest.dev', 'playwright.dev', 'cypress.io', 'selenium.dev',
    'rust-lang.org', 'crates.io', 'go.dev', 'golang.org', 'ruby-lang.org', 'rubygems.org',
    'php.net', 'packagist.org', 'laravel.com', 'symfony.com', 'djangoproject.com', 'flask.palletsprojects.com',
    'fastapi.tiangolo.com', 'spring.io', 'oracle.com', 'java.com', 'kotlinlang.org', 'swift.org',
    'dart.dev', 'flutter.dev', 'dotnet.microsoft.com', 'nuget.org', 'docker.com', 'hub.docker.com',
    'kubernetes.io', 'helm.sh', 'terraform.io', 'hashicorp.com', 'ansible.com', 'jenkins.io',
    'circleci.com', 'travis-ci.org', 'aws.amazon.com', 'amazonaws.com', 'azure.com', 'cloud.google.com',
    'digitalocean.com', 'linode.com', 'akamai.com', 'vultr.com', 'hetzner.com', 'ovhcloud.com',
    'render.com', 'fly.io', 'railway.app', 'heroku.com', 'supabase.com', 'firebase.google.com',
    'planetscale.com', 'neon.tech', 'mongodb.com', 'postgresql.org', 'mysql.com', 'redis.io',
    'elastic.co', 'grafana.com', 'datadoghq.com', 'newrelic.com', 'sentry.io', 'pagerduty.com',
    'statuspage.io', 'fastly.com', 'cloudinary.com', 'imgix.com', 'algolia.com', 'twilio.com',
    'sendgrid.com', 'mailgun.com', 'postmarkapp.com', 'resend.com', 'mailchimp.com', 'brevo.com',
    'hubspot.com', 'salesforce.com', 'zendesk.com', 'intercom.com', 'freshworks.com', 'jira.com',
    'atlassian.net', 'confluence.com', 'okta.com', 'auth0.com', '1password.com', 'bitwarden.com',
    'lastpass.com', 'dashlane.com', 'keepassxc.org', 'yubico.com', 'tailscale.com', 'wireguard.com',
    'openvpn.net', 'nordvpn.com', 'expressvpn.com', 'mullvad.net', 'letsencrypt.org', 'digicert.com',
    'namecheap.com', 'godaddy.com', 'porkbun.com', 'gandi.net', 'squarespace.com', 'wix.com',
    'webflow.com', 'wordpress.com', 'wordpress.org', 'ghost.org', 'substack.com', 'medium.com',
    'dev.to', 'hashnode.com', 'hashnode.dev', 'mirror.xyz', 'blogger.com', 'tumblr.com',
    'patreon.com', 'ko-fi.com', 'buymeacoffee.com', 'gumroad.com', 'lemonsqueezy.com',
    'producthunt.com', 'ycombinator.com', 'crunchbase.com', 'angellist.com', 'wellfound.com',
    'glassdoor.com', 'indeed.com', 'monster.com', 'ziprecruiter.com', 'upwork.com', 'fiverr.com',
    'toptal.com', 'freelancer.com', 'remoteok.com', 'weworkremotely.com',
    // Social, Messaging & Communities
    'x.com', 'threads.net', 'bsky.app', 'mastodon.social', 'snapchat.com', 'quora.com',
    'meetup.com', 'eventbrite.com', 'lu.ma', 'nextdoor.com', 'strava.com', 'alltrails.com',
    'pinterest.co.uk', 'pinterest.de', 'pinterest.fr', 'pinterest.jp', 'pinterest.ca', 'pinimg.com',
    'pin.it', 'messenger.com', 'signal.org', 'viber.com', 'line.me', 'wechat.com', 'qq.com',
    'weibo.com', 'bilibili.com', 'douyin.com', 'kuaishou.com', 'vk.com', 'ok.ru',
    'clubhouse.com', 'guilded.gg', 'matrix.org', 'element.io', 'mattermost.com', 'zulip.com',
    // AI & Research
    'chatgpt.com', 'claude.ai', 'perplexity.ai', 'mistral.ai', 'cohere.com', 'groq.com',
    'together.ai', 'replicate.com', 'stability.ai', 'midjourney.com', 'runwayml.com',
    'elevenlabs.io', 'suno.com', 'poe.com', 'character.ai', 'deepseek.com', 'x.ai',
    'arxiv.org', 'scholar.google.com', 'researchgate.net', 'academia.edu', 'ieee.org',
    'acm.org', 'springer.com', 'sciencedirect.com', 'nature.com', 'science.org', 'nih.gov',
    'pubmed.ncbi.nlm.nih.gov', 'who.int', 'cdc.gov', 'nasa.gov', 'esa.int', 'cern.ch',
    // Education & Reference
    'wikimedia.org', 'wiktionary.org', 'wikidata.org', 'archive.org', 'britannica.com',
    'merriam-webster.com', 'dictionary.com', 'thesaurus.com', 'cambridge.org', 'oxfordlearnersdictionaries.com',
    'coursera.org', 'udemy.com', 'edx.org', 'khanacademy.org', 'udacity.com', 'pluralsight.com',
    'codecademy.com', 'freecodecamp.org', 'scrimba.com', 'egghead.io', 'frontendmasters.com',
    'skillshare.com', 'masterclass.com', 'duolingo.com', 'quizlet.com', 'kahoot.it', 'chegg.com',
    'mit.edu', 'stanford.edu', 'harvard.edu', 'berkeley.edu', 'cmu.edu', 'ox.ac.uk', 'cam.ac.uk',
    'ui.ac.id', 'itb.ac.id', 'ugm.ac.id', 'its.ac.id', 'ipb.ac.id', 'unpad.ac.id', 'binus.ac.id',
    'w3.org', 'w3schools.com', 'mdn.dev', 'developer.mozilla.org', 'web.dev', 'caniuse.com',
    'owasp.org', 'nist.gov', 'cisa.gov', 'mitre.org', 'cve.org', 'nvd.nist.gov',
    // Global News, Tech Media & Publishing
    'nytimes.com', 'washingtonpost.com', 'wsj.com', 'ft.com', 'economist.com', 'bloomberg.com',
    'reuters.com', 'apnews.com', 'bbc.com', 'bbc.co.uk', 'theguardian.com', 'cnn.com', 'cnbc.com',
    'forbes.com', 'businessinsider.com', 'time.com', 'theatlantic.com', 'newyorker.com', 'wired.com',
    'theverge.com', 'techcrunch.com', 'arstechnica.com', 'engadget.com', 'gizmodo.com', 'cnet.com',
    'zdnet.com', 'tomshardware.com', 'anandtech.com', 'gsmarena.com', '9to5mac.com', '9to5google.com',
    'macrumors.com', 'androidauthority.com', 'xda-developers.com', 'bleepingcomputer.com',
    'thehackernews.com', 'krebsonsecurity.com', 'darkreading.com', 'schneier.com', 'lwn.net',
    'slashdot.org', 'hindustantimes.com', 'aljazeera.com', 'dw.com', 'france24.com', 'nhk.or.jp',
    'nikkei.com', 'scmp.com', 'straitstimes.com', 'channelnewsasia.com', 'abc.net.au', 'cbc.ca',
    // E-Commerce, Retail & Marketplaces
    'ebay.com', 'etsy.com', 'walmart.com', 'target.com', 'bestbuy.com', 'costco.com', 'homedepot.com',
    'lowes.com', 'ikea.com', 'wayfair.com', 'macys.com', 'nordstrom.com', 'nike.com', 'adidas.com',
    'uniqlo.com', 'zara.com', 'hm.com', 'sephora.com', 'ulta.com', 'aliexpress.com', 'alibaba.com',
    'taobao.com', 'tmall.com', 'jd.com', 'temu.com', 'shein.com', 'rakuten.co.jp', 'mercadolibre.com',
    'flipkart.com', 'shopify.com', 'myshopify.com', 'woocommerce.com', 'bigcommerce.com',
    'craigslist.org', 'poshmark.com', 'depop.com', 'mercari.com', 'stockx.com', 'goat.com',
    'newegg.com', 'bhphotovideo.com', 'microcenter.com', 'discogs.com', 'bookshop.org', 'barnesandnoble.com',
    // Travel, Maps, Food & Mobility
    'booking.com', 'airbnb.com', 'expedia.com', 'hotels.com', 'agoda.com', 'tripadvisor.com',
    'kayak.com', 'skyscanner.com', 'trip.com', 'vrbo.com', 'marriott.com', 'hilton.com', 'hyatt.com',
    'delta.com', 'united.com', 'aa.com', 'southwest.com', 'lufthansa.com', 'emirates.com',
    'singaporeair.com', 'qatarairways.com', 'garuda-indonesia.com', 'airasia.com',
    'uber.com', 'lyft.com', 'doordash.com', 'ubereats.com', 'grubhub.com', 'instacart.com',
    'deliveroo.com', 'opentable.com', 'yelp.com', 'zomato.com', 'openstreetmap.org', 'mapbox.com',
    'waze.com', 'flightradar24.com', 'flightaware.com', 'rome2rio.com',
    // Global Finance, Banking & Crypto
    'visa.com', 'mastercard.com', 'discover.com', 'capitalone.com', 'usbank.com', 'pnc.com',
    'td.com', 'rbc.com', 'scotiabank.com', 'bmo.com', 'hsbc.com', 'barclays.co.uk', 'lloydsbank.co.uk',
    'natwest.com', 'santander.com', 'ing.com', 'deutsche-bank.de', 'ubs.com', 'bnpparibas.com',
    'dbs.com', 'ocbc.com', 'uobgroup.com', 'maybank2u.com.my', 'commbank.com.au', 'anz.com.au',
    'westpac.com.au', 'nab.com.au', 'fidelity.com', 'vanguard.com', 'schwab.com', 'etrade.com',
    'robinhood.com', 'interactivebrokers.com', 'tradingview.com', 'yahoo.finance.com', 'morningstar.com',
    'investopedia.com', 'nerdwallet.com', 'creditkarma.com', 'intuit.com', 'turbotax.com', 'quickbooks.com',
    'xero.com', 'freshbooks.com', 'square.com', 'squareup.com', 'adyen.com', 'klarna.com', 'affirm.com',
    'plaid.com', 'venmo.com', 'cash.app', 'payoneer.com', 'skrill.com', 'kraken.com', 'gemini.com',
    'okx.com', 'bybit.com', 'coingecko.com', 'coinmarketcap.com', 'etherscan.io', 'solscan.io',
    'metamask.io', 'phantom.app', 'ledger.com', 'trezor.io',
    // Streaming, Entertainment & Music
    'hulu.com', 'disneyplus.com', 'max.com', 'hbomax.com', 'primevideo.com', 'peacocktv.com',
    'paramountplus.com', 'crunchyroll.com', 'funimation.com', 'vidio.com', 'viu.com', 'wetv.vip',
    'iq.com', 'mubi.com', 'plex.tv', 'jellyfin.org', 'deezer.com', 'tidal.com', 'pandora.com',
    'last.fm', 'genius.com', 'ultimate-guitar.com', 'ticketmaster.com', 'stubhub.com', 'livenation.com',
    // Indonesia Major Portals, Media, Telco, Services & Gov
    'kompas.com', 'kompas.id', 'detik.com', 'cnnindonesia.com', 'cnbcindonesia.com', 'tempo.co',
    'liputan6.com', 'tribunnews.com', 'kumparan.com', 'katadata.co.id', 'kontan.co.id', 'bisnis.com',
    'tirto.id', 'idntimes.com', 'suara.com', 'okezone.com', 'sindonews.com', 'antaranews.com',
    'republika.co.id', 'jawapos.com', 'merdeka.com', 'viva.co.id', 'kapanlagi.com', 'bola.net',
    'kaskus.co.id', 'qubisa.com', 'ruangguru.com', 'zenius.net', 'dicoding.com', 'buildwithangga.com',
    'halodoc.com', 'alodokter.com', 'klikdokter.com', 'pedulilindungi.id', 'satusehat.kemkes.go.id',
    'indosat.co.id', 'xl.co.id', 'smartfren.com', 'indihome.co.id', 'biznetnetworks.com',
    'myrepublic.co.id', 'pln.co.id', 'pertamina.com', 'kai.id', 'posindonesia.co.id',
    'jne.co.id', 'jet.co.id', 'sicepat.com', 'anteraja.id', 'jntexpress.id', 'lionparcel.com',
    'pegadaian.co.id', 'bpjs-kesehatan.go.id', 'bpjsketenagakerjaan.go.id', 'kemdikbud.go.id',
    'kemenkeu.go.id', 'kominfo.go.id', 'ojk.go.id', 'bi.go.id', 'bps.go.id', 'go.id',
    'bibit.id', 'stockbit.com', 'bareksa.com', 'ajaib.co.id', 'pluang.com', 'indodax.com',
    'tokocrypto.com', 'pintu.co.id', 'flip.id', 'xendit.co', 'midtrans.com', 'doku.com',
    'linkaja.id', 'kredivo.com', 'akulaku.com', 'jago.com', 'seabank.co.id', 'jenius.com',
    'blu.id', 'bankmega.com', 'danamon.co.id', 'permatabank.com', 'ocbc.id', 'maybank.co.id',
    'panin.co.id', 'btn.co.id', 'pegipegi.com', 'olx.co.id', 'rumah123.com', 'lamudi.co.id',
    'mamikos.com', 'glints.com', 'kalibrr.com', 'jobstreet.co.id', 'karir.com', 'dealls.com',
    'sociolla.com', 'zalora.co.id', 'mapclub.com', 'ruparupa.com', 'bhinneka.com', 'eraspace.com',
    'ibox.co.id', 'digimap.co.id', 'gramedia.com', 'alfagift.id', 'klikindomaret.com',
    // Government, Standards & Misc
    'usa.gov', 'irs.gov', 'gov.uk', 'europa.eu', 'un.org', 'ietf.org', 'icann.org', 'iana.org',
    'linux.org', 'kernel.org', 'ubuntu.com', 'debian.org', 'fedoraproject.org', 'archlinux.org',
    'gnu.org', 'fsf.org', 'apache.org', 'eclipse.org', 'cncf.io', 'eff.org', 'signal.org',
    'torproject.org', 'creativecommons.org', 'openstreetmap.org', 'weather.com', 'accuweather.com',
    'speedtest.net', 'fast.com', 'virustotal.com', 'shodan.io', 'crt.sh', 'whois.com',
    'example.com', 'example.org', 'example.net'
  ]);

  // Commonly abused TLDs in phishing campaigns
  const SUSPICIOUS_TLDS = new Set([
    'xyz', 'top', 'zip', 'tk', 'ml', 'ga', 'cf', 'gq',
    'click', 'link', 'buzz', 'work', 'support', 'security', 'account',
    'login', 'verify', 'icu', 'vip', 'loan', 'win', 'rest', 'cam',
    'mov', 'cfd', 'sbs', 'pw'
  ]);

  // Shared free-hosting public suffixes frequently abused for credential phishing
  const FREE_HOSTING_SUFFIXES = new Set([
    'github.io', 'gitlab.io', 'pages.dev', 'workers.dev', 'vercel.app',
    'netlify.app', 'web.app', 'firebaseapp.com', 'herokuapp.com',
    'appspot.com', 'azurewebsites.net'
  ]);

  // Legitimate payment processors allowed as cross-origin credit-card form targets
  const KNOWN_PAYMENT_PROCESSORS = new Set([
    'stripe.com', 'paypal.com', 'adyen.com', 'braintreegateway.com',
    'squareup.com', 'square.com', 'shopify.com', 'checkout.com',
    'midtrans.com', 'xendit.co', 'doku.com', 'klarna.com', 'razorpay.com'
  ]);

  const exportsObj = {
    DEFAULT_PROTECTED_DOMAINS,
    TOP_TRUSTED_DOMAINS,
    MULTI_PART_TLDS,
    FREE_HOSTING_SUFFIXES,
    KNOWN_PAYMENT_PROCESSORS,
    SIBLING_DOMAIN_GROUPS,
    SIBLING_GROUP_INDEX,
    KNOWN_OAUTH_HOSTS,
    KNOWN_OAUTH_DOMAINS,
    SUSPICIOUS_TLDS
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exportsObj;
  }
  root.PhishGuardDomains = exportsObj;
})(typeof globalThis !== 'undefined' ? globalThis : this);
