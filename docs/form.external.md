The page uses HTTPS which is great for your users.

The page uses HTTPS which is great for your users.
However, when there is a form on the page, it submits to a non-secured page (be it internal or external pages). Browsers will therefore change your "secure" page to "insecure" in the URL bar. Firefox takes this a step further and shows a 'dialog warning' to users that they are submitting to a 'non-secured page' in a dialog. Users are asked to click "continue" if they want to take the risk, which is a rather scary message.

This happens because one of the forms on the page has its action= set to a http:// page from a https:// page.

Look for something like the following:

```
<form method="POST" url="http://external.example.com/add">
```

# How do I fix this ?

Ensure the target page for your form supports https as well. Then change the URL to the https version of the URL:

```
<form method="POST" url="https://external.example.com/add">
```

# Resources

* [How do I disable the "Security Warning" - encrypted script message when I log in to a website using https ?](https://support.mozilla.org/en-US/questions/1012395)