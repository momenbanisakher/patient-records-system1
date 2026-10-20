(function () {
  "use strict";

  // 1) منع اختيار تاريخ في المستقبل
  var today = new Date().toISOString().slice(0, 10);
  document.querySelectorAll("input[data-max-today]").forEach(function (el) {
    el.setAttribute("max", today);
  });

  // 2) تأكيد قبل الإجراءات الخطرة (مثل الحذف)
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (e) {
      if (!window.confirm(form.getAttribute("data-confirm"))) {
        e.preventDefault();
      }
    });
  });

  // 3) بحث فوري عن المرضى
  var input = document.getElementById("searchInput");
  var body = document.getElementById("patientsBody");
  if (!input || !body) {
    return;
  }

  var pager = document.getElementById("pager");
  var searchForm = document.getElementById("searchForm");
  var timer = null;
  var lastQuery = input.value;

  function setSearching(isSearching) {
    if (!searchForm) {
      return;
    }
    searchForm.classList.toggle("is-searching", isSearching);
  }

  function cell(text, ltr) {
    var td = document.createElement("td");
    if (ltr) {
      td.setAttribute("dir", "ltr");
      td.className = "text-end";
    }
    td.textContent = text;
    return td;
  }

  function render(rows) {
    body.textContent = "";
    if (!rows.length) {
      var tr = document.createElement("tr");
      var td = cell("لا توجد نتائج.", false);
      td.colSpan = 5;
      td.className = "text-center text-muted py-4";
      tr.appendChild(td);
      body.appendChild(tr);
      return;
    }
    rows.forEach(function (p) {
      var tr = document.createElement("tr");
      tr.appendChild(cell(p.file_no, true));
      var nameTd = document.createElement("td");
      var a = document.createElement("a");
      a.href = p.url;
      a.textContent = p.full_name;
      nameTd.appendChild(a);
      tr.appendChild(nameTd);
      tr.appendChild(cell(p.dob, false));
      tr.appendChild(cell(p.gender, false));
      tr.appendChild(cell(p.phone, true));
      body.appendChild(tr);
    });
  }

  function search() {
    var q = input.value.trim();
    if (q === lastQuery) {
      return;
    }
    lastQuery = q;
    var url = input.getAttribute("data-search-url") + "?q=" + encodeURIComponent(q);
    setSearching(true);
    fetch(url, { headers: { Accept: "application/json" }, credentials: "same-origin" })
      .then(function (r) {
        if (!r.ok) {
          throw new Error("search failed");
        }
        return r.json();
      })
      .then(function (rows) {
        if (input.value.trim() !== q) {
          return; // وصلت نتيجة قديمة
        }
        render(rows);
        if (pager) {
          pager.style.display = "none";
        }
      })
      .catch(function () {
        /* نُبقي النتائج الحالية عند الفشل */
      })
      .finally(function () {
        setSearching(false);
      });
  }

  input.addEventListener("input", function () {
    clearTimeout(timer);
    timer = setTimeout(search, 250);
  });
})();
