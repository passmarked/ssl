HTTPS allows websites to secure their users by not allowing any man-in-the-middle attacks. This keeps users' data secure and ensures that no nefarious eyes can peek and steal user data.

The page uses HTTPS which is great, your users are thankfull. But when there is a form on the page submits to a non-secured page (be it internal or external pages) browsers will change your "secure" page to "insecure" in the url bar. Firefox takes this a step further and shows a dialog warning users that they are submitting to a non-secured page in a dialog, where the user needs to click "continue" after a scary message.

This happens because one of the forms on the page has it's `action=` set to a http:// page from a https:// page. 

Look for something like the following:

```
<form method="POST" url="http://extenal.example.com/add">
```

# How do I fix this ?

Ensure the target page for your form supportshttps as well. Then change the URL to the https version of the URL:

```
<form method="POST" url="https://extenal.example.com/add">
```

# Resources

* [How do I disable the "Security Warning" - encrpted script message when I log in to a website using https ?](https://support.mozilla.org/en-US/questions/1012395)