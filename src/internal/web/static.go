package web

import (
	_ "embed"
	"net/http"
)

//go:embed static/style.css
var styleSheet string

// checkScript is the check page's one script: while the check runs, it
// asks GET /api/checks/<id> every two seconds and reloads the page when
// the status or the number of steps changed, so every value on the page is
// rendered by html/template and none by the script. It reads the check's
// ID and what the page shows from the body's data attributes, never from
// a script built from server data. It is kept here, not in a .js file,
// because the Standard's ESLint lints every .js file against tsconfig.json.
const checkScript = `"use strict";
(function () {
  var body = document.body;
  var id = body.dataset.checkId;
  var settled = ["done", "failed", "waiting"];
  if (!id || settled.indexOf(body.dataset.status) >= 0) {
    return;
  }
  function poll() {
    fetch("/api/checks/" + encodeURIComponent(id), {
      headers: { accept: "application/json" },
      cache: "no-store",
    })
      .then(function (resp) {
        return resp.ok ? resp.json() : null;
      })
      .then(function (check) {
        if (
          check &&
          (check.status !== body.dataset.status ||
            String(check.steps.length) !== body.dataset.steps)
        ) {
          window.location.reload();
          return;
        }
        window.setTimeout(poll, 2000);
      })
      .catch(function () {
        window.setTimeout(poll, 2000);
      });
  }
  window.setTimeout(poll, 2000);
})();
`

// staticFiles are the files under /static/, with their content types.
var staticFiles = map[string]struct{ contentType, body string }{
	"check.js":  {"text/javascript; charset=utf-8", checkScript},
	"style.css": {"text/css; charset=utf-8", styleSheet},
}

// staticFile answers GET /static/<name>.
func staticFile(name string) (Response, error) {
	f, ok := staticFiles[name]
	if !ok {
		return problem(http.StatusNotFound, "No file "+quotable(name)+"."), nil
	}
	return Response{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"content-type": f.contentType, "cache-control": "public, max-age=300"},
		Body:       f.body,
	}, nil
}
