---
created: 2025-05-07
published: 2025-05-16
lastmod: 2025-05-16
tags:
- learning
- file upload
- xxe
- svg
- php filters
- blacklists
- whitelists
- mime type
- content-type
image: /static/note-thumbnails/htb-file-upload-attacks.webp
description: Throughout this module, I learn the basics of identifying and exploiting file upload vulnerabilities and identifying and mitigating basic security restrictions in place to reach arbitrary file uploads.
---

<img src="/static/note-thumbnails/htb-file-upload-attacks.webp" alt="htb file upload attacks logo" style="max-width: 450px; height: auto; display: block; margin: 0 auto; box-shadow: 0px 0px 14px 0px rgba(0,0,0,0.9);">

Time to complete: ~10 hours

https://academy.hackthebox.com/achievement/402127/136

Learnt skills:

- Able to detect and exploit file upload forms with no validations or filters
- Can bypass client-side/front-end upload controls to upload arbitrary files
- Able to identify what extensions are not blacklisted and use them to gain code execution
- Able to identify what extensions are whitelisted and whether they can be bypassed to upload arbitrary files
- Able to detect type/content validations and bypass them using fake content headers and file signatures
- Can work with various types of limited file upload forms and attack them based on the file types they allow
- Can attempt various other attacks with file upload forms
- Able to report file upload vulnerabilities and their mitigations, along with recommendations on how to protect the web application against future attacks

<img src="/static/completed-thumbnails/htb-file-upload-attacks.png" alt="htb writeup" style="max-width: 450px; height: auto; display: block; margin: 0 auto; box-shadow: 0px 0px 14px 0px rgba(0,0,0,0.9);">
